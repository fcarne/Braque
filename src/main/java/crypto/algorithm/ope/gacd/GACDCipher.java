package crypto.algorithm.ope.gacd;

import crypto.EngineAutoBindable;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class GACDCipher extends CipherSpi implements EngineAutoBindable {

    public static final String ALGORITHM_NAME = "CommonDivisor";

    private int opmode;
    private SecureRandom secureRandom;

    private BigInteger k;

    @Override
    public String getBind() {
        return "Cipher." + ALGORITHM_NAME;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("GACD does not support different modes");
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("GACD does not support different padding mechanisms");
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
        this.secureRandom = secureRandom;
        if (key instanceof GACDSecretKeySpec) {
            GACDSecretKeySpec.Raw raw = ((GACDSecretKeySpec) key).decodeKey();
            k = raw.getK();
        } else throw new InvalidKeyException("The key used is not a GACD Key");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException();
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException {
        engineInit(opmode, key, secureRandom);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] output = null;
        if (opmode == Cipher.ENCRYPT_MODE) {
            output = new byte[k.toByteArray().length * 2];
        } else if (opmode == Cipher.DECRYPT_MODE) {
            output = new byte[Long.BYTES];
        }
        engineUpdate(input, inputOffset, inputLen, output, 0);
        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (opmode == Cipher.ENCRYPT_MODE) {
            long m = ByteBuffer.wrap(input).getLong();

            BigInteger kPow = BigDecimal.valueOf(Math.pow(k.doubleValue(), 3.0/4)).toBigInteger();
            BigInteger r = new BigInteger(k.bitLength(), secureRandom).mod(k.subtract(BigInteger.TWO.multiply(kPow))).add(kPow);
            BigInteger c = BigInteger.valueOf(m).multiply(k).add(r);

            byte[] cipherArray = c.toByteArray();
            System.arraycopy(cipherArray, 0, output, output.length - cipherArray.length, cipherArray.length);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            BigInteger c = new BigInteger(input);
            long m = c.divide(k).longValue();

            System.arraycopy(ByteBuffer.allocate(Long.BYTES).putLong(m).array(), 0, output, 0, output.length);
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

}
