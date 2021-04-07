package crypto.algorithm.ope.piore;

import crypto.EngineAutoBindable;
import crypto.algorithm.ope.GaloisPRF;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class PIORECipher extends CipherSpi implements EngineAutoBindable {

    public static final String ALGORITHM_NAME = "PIOre";

    private int opmode;

    private byte[] k;
    private BigInteger m;
    private byte n;

    private int mPowerNBytesLength;

    @Override
    public String getBind() {
        return "Cipher." + ALGORITHM_NAME;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException(ALGORITHM_NAME + " does not support different modes");
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
        if (key instanceof PIORESecretKeySpec) {
            PIORESecretKeySpec.Raw raw = ((PIORESecretKeySpec) key).decodeKey();
            k = raw.getK();
            m = BigInteger.TWO.pow(raw.getM());
            n = raw.getN();

            mPowerNBytesLength = m.pow(n).toByteArray().length;
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
            output = new byte[mPowerNBytesLength];
        } else if (opmode == Cipher.DECRYPT_MODE) {
            output = new byte[Long.BYTES];
        }
        engineUpdate(input, inputOffset, inputLen, output, 0);
        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (opmode == Cipher.ENCRYPT_MODE) {
            long b = ByteBuffer.wrap(input).getLong();

            BigInteger cipher = BigInteger.ZERO;
            for (int i = 1; i <= n; i++) {
                BigInteger uI = f(i, b);
                cipher = m.pow(n - i).multiply(uI).add(cipher);
            }

            byte[] cipherArray = cipher.toByteArray();
            System.arraycopy(cipherArray, 0, output, output.length - cipherArray.length, cipherArray.length);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            BigInteger c = new BigInteger(input);

            long b = 0;

            BigInteger[] u = new BigInteger[n];
            for (int i = n - 1; i >= 0; i--) {
                BigInteger[] quotientAndRemainder = c.divideAndRemainder(m);
                c = quotientAndRemainder[0];
                u[i] = quotientAndRemainder[1];
            }

            for (int i = 1; i <= n; i++) {
                if (u[i - 1].compareTo(f(i, b)) != 0) {
                    b |= 1L << (n - i);
                }
            }

            if (!c.equals(BigInteger.ZERO)) {
                b = Long.MIN_VALUE;
            }

            System.arraycopy(ByteBuffer.allocate(Long.BYTES).putLong(b).array(), 0, output, 0, output.length);
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

    private BigInteger f(int i, long b) {
        int shift = n - i + 1;
        int bI = (int) ((b >> (n - i)) & 1);
        b = b >> shift << shift;

        byte[] hash = GaloisPRF.generate(k, i, b);
        return new BigInteger(hash).add(BigInteger.valueOf(bI)).mod(m);
    }
}
