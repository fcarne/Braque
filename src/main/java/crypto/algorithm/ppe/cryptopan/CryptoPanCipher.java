package crypto.algorithm.ppe.cryptopan;

import crypto.EngineAutoBindable;
import util.BitSetUtils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.BitSet;

public abstract class CryptoPanCipher extends CipherSpi implements EngineAutoBindable {

    protected static final String ALGORITHM_NAME = "CryptoPan";

    private int opmode;
    private CryptoPanAlgorithmParameterSpec parameterSpec = new CryptoPanAlgorithmParameterSpec();
    private boolean suffixMode;

    private Cipher cipher;
    private BitSet padBits;
    private BitSet[] shiftedPad;

    public static class Prefix extends CryptoPanCipher {

        public static final String ALGORITHM_NAME = CryptoPanCipher.ALGORITHM_NAME;

        public Prefix() throws NoSuchAlgorithmException {
            engineSetMode("Prefix");
        }

        @Override
        public String getBind() {
            return "Cipher." + ALGORITHM_NAME;
        }
    }

    public static class Suffix extends CryptoPanCipher {

        public static final String ALGORITHM_NAME = CryptoPanCipher.ALGORITHM_NAME + ".Suffix";

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
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException(ALGORITHM_NAME + " does not support different padding mechanisms");
    }

    @Override
    protected int engineGetBlockSize() {
        return 1;
    }

    @Override
    protected int engineGetOutputSize(int i) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        this.opmode = opmode;
        if (key instanceof CryptoPanSecretKeySpec) {
            CryptoPanSecretKeySpec.Raw raw = ((CryptoPanSecretKeySpec) key).decodeKey();
            SecretKeySpec cipherKey = new SecretKeySpec(raw.getKey(), "AES");
            try {
                cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, cipherKey);

                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                random.setSeed(raw.getPad());

                byte[] padBytes = new byte[parameterSpec.getMaxLength()];
                random.nextBytes(padBytes);

                byte[] pad = Arrays.copyOfRange(cipher.doFinal(padBytes), 0, parameterSpec.getMaxLength());
                padBits = BitSet.valueOf(pad);

                shiftedPad = new BitSet[parameterSpec.getBitsMaxLength()];

            } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            }

        } else throw new InvalidKeyException("The key used is not a " + ALGORITHM_NAME + " Key");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (algorithmParameterSpec instanceof CryptoPanAlgorithmParameterSpec) {
            parameterSpec = (CryptoPanAlgorithmParameterSpec) algorithmParameterSpec;
        } else throw new InvalidAlgorithmParameterException();
        engineInit(opmode, key, secureRandom);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException {
        engineInit(opmode, key, secureRandom);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] output = null;
        if (opmode == Cipher.ENCRYPT_MODE) {
            output = new byte[inputLen];
        } else if (opmode == Cipher.DECRYPT_MODE) {
            output = new byte[inputLen];
        }
        engineUpdate(input, inputOffset, inputLen, output, 0);
        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {

        if (suffixMode) {
            input = reverse(input);
        }

        ByteBuffer buffer = ByteBuffer.allocate(parameterSpec.getMaxLength()).put(input);

        BitSet original = BitSetUtils.fromBigEndian(buffer);
        int bitsLength = parameterSpec.getBitsMaxLength();

        if (opmode == Cipher.ENCRYPT_MODE) {
            BitSet result = new BitSet(parameterSpec.getMaxLength() * 8);

            for (int pos = 0; pos < inputLen * 8; pos++) {

                BitSet otp = calculateOTP(original, padBits, pos);
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

            byte[] resultArray = Arrays.copyOfRange(BitSetUtils.toBigEndian(result), 0, inputLen);

            if (suffixMode) {
                resultArray = reverse(resultArray);
            }

            System.arraycopy(resultArray, 0, output, 0, output.length);

        } else if (opmode == Cipher.DECRYPT_MODE) {

            for (int pos = 0; pos < inputLen * 8; pos++) {

                BitSet otp = calculateOTP(original, padBits, pos);
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

            byte[] originalArray = Arrays.copyOfRange(BitSetUtils.toBigEndian(original), 0, inputLen);

            if (suffixMode) {
                originalArray = reverse(originalArray);
            }

            System.arraycopy(originalArray, 0, output, 0, output.length);
        }

        return inputLen;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        return engineUpdate(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        return engineUpdate(input, inputOffset, inputLen, output, outputOffset);
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

    private BitSet calculateOTP(BitSet original, BitSet padBits, int pos) {

        int length = parameterSpec.getBitsMaxLength();

        BitSet mask = new BitSet(length);
        mask.set(length - pos, length);

        BitSet otp;

        if (shiftedPad[pos] != null) {
            otp = (BitSet) shiftedPad[pos].clone();
        } else {
            otp = BitSetUtils.shiftLeft(padBits, pos);
            otp.or(BitSetUtils.shiftRight(padBits, length - pos));

            shiftedPad[pos] = (BitSet) otp.clone();
        }

        /*if (pos == 0) {
            mask.clear();
            otp = padBits;
        }*/
        mask.and(original);
        otp.xor(mask);

        return otp;
    }

}
