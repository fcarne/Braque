package crypto.algorithm.ppe.stott;

import crypto.algorithm.GaloisCipher;
import crypto.algorithm.util.FluentBitSet;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.BitSet;

public abstract class StottCipher extends GaloisCipher {

    protected static final String ALGORITHM_NAME = "Stott";

    private StottParameterSpec parameterSpec = new StottParameterSpec();
    private boolean suffixMode;

    private Cipher cipher;
    private BitSet padBits;
    private BitSet[] shiftedPad;

    public static class Prefix extends StottCipher {

        public static final String ALGORITHM_NAME = StottCipher.ALGORITHM_NAME;

        public Prefix() throws NoSuchAlgorithmException {
            engineSetMode("Prefix");
        }

        @Override
        public String getBind() {
            return "Cipher." + ALGORITHM_NAME;
        }
    }

    public static class Suffix extends StottCipher {

        public static final String ALGORITHM_NAME = StottCipher.ALGORITHM_NAME + ".Suffix";

        public Suffix() throws NoSuchAlgorithmException {
            engineSetMode("Suffix");
        }

        @Override
        public String getBind() {
            return "Cipher." + ALGORITHM_NAME;
        }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (mode.equals("Prefix")) {
            suffixMode = false;
        } else if (mode.equals("Suffix")) {
            suffixMode = true;
        } else
            throw new NoSuchAlgorithmException(ALGORITHM_NAME + " does not support this mode, only 'Prefix' and 'Suffix' modes");
    }


    @Override
    protected int engineGetOutputSize(int inputLen) {
        return inputLen;
    }

    @Override
    protected void engineInit(int opMode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        this.opMode = opMode;
        byte[] keyBytes = getKeyBytes(key);
        StottSecretKey stottKey = new StottSecretKey(keyBytes);

        SecretKeySpec cipherKey = new SecretKeySpec(stottKey.getCipherKey(), StottSecretKey.CIPHER_ALGORITHM);
        try {
            cipher = Cipher.getInstance(StottSecretKey.CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, cipherKey);

            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(stottKey.getPadSeed());

            byte[] padBytes = new byte[parameterSpec.getMaxLength()];
            random.nextBytes(padBytes);

            byte[] pad = Arrays.copyOfRange(cipher.doFinal(padBytes), 0, parameterSpec.getMaxLength());
            padBits = BitSet.valueOf(pad);

            shiftedPad = new BitSet[parameterSpec.getBitsMaxLength()];

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

    }

    @Override
    protected void engineInit(int opMode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (algorithmParameterSpec instanceof StottParameterSpec) {
            parameterSpec = (StottParameterSpec) algorithmParameterSpec;
        } else
            throw new InvalidAlgorithmParameterException("algorithmParameterSpec must be of type " + StottParameterSpec.class.getName());
        engineInit(opMode, key, secureRandom);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {

        if (suffixMode) {
            input = reverse(input);
        }

        int bitsLength = parameterSpec.getBitsMaxLength();
        ByteBuffer buffer = ByteBuffer.allocate(parameterSpec.getMaxLength()).put(input);
        FluentBitSet original = FluentBitSet.valueOf(buffer, ByteOrder.BIG_ENDIAN);

        if (opMode == Cipher.ENCRYPT_MODE) {
            FluentBitSet result = new FluentBitSet(parameterSpec.getMaxLength() * 8);

            for (int pos = 0; pos < inputLen * 8; pos++) {
                FluentBitSet otp = calculateOTP(original, padBits, pos);

                byte[] cipherInput = otp.toByteArray();
                byte[] cipherOutput = new byte[0];
                try {
                    cipherOutput = Arrays.copyOfRange(cipher.doFinal(cipherInput), 0, parameterSpec.getMaxLength());
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }

                BitSet msb = new BitSet(bitsLength - pos);
                msb.set(bitsLength - 1 - pos, BitSet.valueOf(cipherOutput).get(bitsLength - 1));
                result.or(msb);

            }
            result.xor(original);

            byte[] resultArray = Arrays.copyOfRange(result.toByteArray(ByteOrder.BIG_ENDIAN), 0, inputLen);

            if (suffixMode) {
                resultArray = reverse(resultArray);
            }

            System.arraycopy(resultArray, 0, output, 0, output.length);

        } else if (opMode == Cipher.DECRYPT_MODE) {

            for (int pos = 0; pos < inputLen * 8; pos++) {
                FluentBitSet otp = calculateOTP(original, padBits, pos);

                byte[] cipherInput = otp.toByteArray();
                byte[] cipherOutput = new byte[0];
                try {
                    cipherOutput = Arrays.copyOfRange(cipher.doFinal(cipherInput), 0, parameterSpec.getMaxLength());
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }

                BitSet msb = new BitSet(bitsLength - pos);
                msb.set(bitsLength - 1 - pos, BitSet.valueOf(cipherOutput).get(bitsLength - 1));
                original.xor(msb);
            }

            byte[] originalArray = Arrays.copyOfRange(original.toByteArray(ByteOrder.BIG_ENDIAN), 0, inputLen);

            if (suffixMode) {
                originalArray = reverse(originalArray);
            }

            System.arraycopy(originalArray, 0, output, 0, output.length);
        }

        return inputLen;
    }

    public static byte[] reverse(byte[] input) {
        byte[] reversed = new byte[input.length];
        for (int j = 0; j < input.length; j++) {
            for (int i = 0; i < 8; i++) {
                reversed[input.length - j - 1] <<= 1;
                reversed[input.length - j - 1] |= (input[j] >> i) & 0x1;
            }
        }
        return reversed;
    }

    private FluentBitSet calculateOTP(FluentBitSet original, BitSet padBits, int pos) {

        int length = parameterSpec.getBitsMaxLength();

        FluentBitSet mask = new FluentBitSet(length).set(length - pos, length);
        FluentBitSet otp;

        if (shiftedPad[pos] != null) {
            otp = FluentBitSet.valueOf(shiftedPad[pos]);
        } else {
            otp = FluentBitSet.valueOf(padBits).shiftLeft(pos).
                    or(FluentBitSet.valueOf(padBits).shiftRight(length - pos));

            shiftedPad[pos] = (BitSet) otp.getBitSet().clone();
        }
        otp.xor(mask.and(original));

        return otp;
    }

}
