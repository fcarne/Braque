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

public class CryptoPanCipher extends CipherSpi implements EngineAutoBindable {

    public static final String ALGORITHM_NAME = "CryptoPan";

    private int opmode;
    private CryptoPanAlgorithmParameterSpec parameterSpec = new CryptoPanAlgorithmParameterSpec();
    private boolean suffixMode = false;

    private Cipher cipher;
    private byte[] pad;

    @Override
    public String getBind() {
        return "Cipher." + ALGORITHM_NAME;
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

                parameterSpec.setMaxLength(4);
                //SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                //byte[] padBytes = new byte[parameterSpec.getMaxLength()];
                //random.nextBytes(padBytes);
                pad = Arrays.copyOfRange(cipher.doFinal(raw.getPad()), 0, parameterSpec.getMaxLength());


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
            reverse(input);
        }

        ByteBuffer buffer = ByteBuffer.allocate(parameterSpec.getMaxLength()).put(input);
        BitSet original = BitSetUtils.fromBigEndian(buffer);

        BitSet padBits = BitSet.valueOf(pad);

        if (opmode == Cipher.ENCRYPT_MODE) {
            BitSet result = new BitSet(parameterSpec.getMaxLength());

            for (int pos = 0; pos < inputLen * 8; pos++) {

                BitSet otp = calculateOTP(original, padBits, pos);
                byte[] cipherInput = otp.toByteArray();

                byte[] cipherOutput = new byte[0];
                try {
                    cipherOutput = Arrays.copyOfRange(cipher.doFinal(cipherInput), 0, parameterSpec.getMaxLength());
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }

//                BitSet msb2 = BitSetUtils.shiftLeft(BitSetUtils.shiftRight(BitSet.valueOf(cipherOutput), parameterSpec.getBitsMaxLength() - 1), );

                BitSet msb = BitSet.valueOf(cipherOutput);
                msb.and(BitSetUtils.valueOf(0x80000000));
          //      System.out.println(msb + " --- " + msb2);
                result.or(BitSetUtils.shiftRight(msb, pos));

            }
            result.xor(original);

            byte[] resultArray = BitSetUtils.toBigEndian(result);

            if (suffixMode) reverse(resultArray);

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

                BitSet msb = BitSet.valueOf(cipherOutput).get(parameterSpec.getBitsMaxLength() - 1, parameterSpec.getBitsMaxLength());
                //BitSet bitSetOutput = BitSet.valueOf(cipherOutput);
                //bitSetOutput.and(BitSetUtils.valueOf(0x80000000));
                original.xor(BitSetUtils.shiftRight(msb, pos));
            }

            byte[] originalArray = BitSetUtils.toBigEndian(original);

            if (suffixMode) reverse(originalArray);

            System.arraycopy(originalArray, 0, output, 0, output.length);
        }

        return inputLen;
    }

    private BitSet calculateOTP(BitSet original, BitSet padBits, int pos) {

        int length = parameterSpec.getBitsMaxLength();

        BitSet mask = new BitSet(length);
        mask.set(length - pos, length);

        BitSet otp = BitSetUtils.shiftLeft(padBits, pos);
        otp.or(BitSetUtils.shiftRight(padBits, length - pos));

        /*if (pos == 0) {
            mask.clear();
            otp = padBits;
        }*/

        mask.and(original);
        otp.xor(mask);
        return otp;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        return engineUpdate(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        return engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

    private void reverse(byte[] input) {
        for (int j = 0; j < input.length; j++) {
            for (int i = 0; i < 8; i++) {
                input[input.length - j - 1] <<= 1;
                input[input.length - j - 1] |= (input[j] >> i) & 0x1;
            }
        }
    }
}
