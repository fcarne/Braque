package crypto.algorithm.ppe.cryptopan;

import crypto.EngineAutoBindable;
import util.BitSetUtils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.BitSet;

public class CryptoPanCipher extends CipherSpi implements EngineAutoBindable {

    public static final String ALGORITHM_NAME = "CryptoPan";

    private int opmode;
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
                pad = cipher.doFinal(raw.getPad());
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            }

        } else throw new InvalidKeyException("The key used is not a " + ALGORITHM_NAME + " Key");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException {
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
        if (opmode == Cipher.ENCRYPT_MODE) {

            ByteBuffer buffer = ByteBuffer.allocate(4 * Byte.BYTES).put(input);

            BitSet original = BitSet.valueOf(reverseBytes(buffer.array()));
            BitSet result = new BitSet(32);
            BitSet first4bytes_pad = BitSet.valueOf(Arrays.copyOfRange(pad, 0, 4));

            for (int pos = 0; pos < 32; pos++) {

                BitSet otp = calculateOTP(original, first4bytes_pad, pos);

                byte[] cipherInput = otp.toByteArray();
                byte[] cipherOutput = new byte[0];
                try {
                    cipherOutput = Arrays.copyOfRange(cipher.doFinal(cipherInput), 0, 4);
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }

                BitSet bitSetOutput = BitSet.valueOf(cipherOutput);
                bitSetOutput.and(BitSetUtils.valueOf(0x80000000));
                result.or(BitSetUtils.shiftRight(bitSetOutput, pos));

            }

            result.xor(original);

            byte[] resultArray = reverseBytes(result.toByteArray());
            System.arraycopy(resultArray, 0, output, 0, output.length);

        } else if (opmode == Cipher.DECRYPT_MODE) {

            ByteBuffer buffer = ByteBuffer.allocate(4 * Byte.BYTES).put(input);

            BitSet original = BitSet.valueOf(reverseBytes(buffer.array()));
            BitSet first4bytes_pad = BitSet.valueOf(Arrays.copyOfRange(pad, 0, 4));

            for (int pos = 0; pos < 32; pos++) {

                BitSet newpad = calculateOTP(original, first4bytes_pad, pos);

                byte[] cipherInput = newpad.toByteArray();
                byte[] cipherOutput = new byte[0];
                try {
                    cipherOutput = Arrays.copyOfRange(cipher.doFinal(cipherInput), 0, 4);
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }

                BitSet bitSetOutput = BitSet.valueOf(cipherOutput);
                bitSetOutput.and(BitSetUtils.valueOf(0x80000000));
                original.xor(BitSetUtils.shiftRight(bitSetOutput, pos));
            }

            byte[] resultArray = reverseBytes(original.toByteArray());
            System.arraycopy(resultArray, 0, output, 0, output.length);
        }

        return inputLen;
    }

    private BitSet calculateOTP(BitSet original, BitSet first4bytes_pad, int pos) {
        BitSet mask = BitSetUtils.valueOf(-1L << (32 - pos));
        BitSet newpad = BitSetUtils.shiftLeft(first4bytes_pad, pos);
        newpad.or(BitSetUtils.shiftRight(first4bytes_pad, 32 - pos));

        if (pos == 0) {
            // the compile thinks ( -1<<(32-0) = 0xffffffff instead of 0 )
            mask.clear();
            newpad = first4bytes_pad;
        }

        mask.and(original);
        newpad.xor(mask);
        return newpad;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        return engineUpdate(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        return engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

    private byte[] reverse(byte[] input) {
        byte[] reverse = new byte[input.length];
        for (int j = 0; j < input.length; j++) {
            for (int i = 0; i < 8; i++) {
                reverse[reverse.length - j - 1] <<= 1;
                reverse[reverse.length - j - 1] |= (input[j] >> i) & 0x1;
            }
        }
        return reverse;
    }

    private byte[] reverseBytes(byte[] input) {
        byte[] reversed = input.clone();
        for (int i = 0; i < reversed.length / 2; i++) {
            byte temp = reversed[i];
            reversed[i] = reversed[reversed.length - 1 - i];
            reversed[reversed.length - 1 - i] = temp;
        }
        return reversed;
    }
}
