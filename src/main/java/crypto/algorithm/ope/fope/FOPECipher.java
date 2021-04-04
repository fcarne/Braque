package crypto.algorithm.ope.fope;

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

public class FOPECipher extends CipherSpi implements EngineAutoBindable {

    public static final String ALGORITHM_NAME = "FastOPE";

    private int opmode;

    private byte d;
    private byte[] k;

    private BigInteger[] infLimitF;
    private BigInteger[] supLimitF;

    private int nBytesLength;

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
        if (key instanceof FOPESecretKeySpec) {
            FOPESecretKeySpec.Raw raw = ((FOPESecretKeySpec) key).decodeKey();

            BigDecimal alpha = BigDecimal.valueOf(raw.getAlpha());
            BigDecimal beta = BigDecimal.valueOf(raw.getBeta());
            BigDecimal n = BigDecimal.valueOf((raw.getN()));
            BigDecimal e = BigDecimal.valueOf(raw.getE());
            k = raw.getK();
            d = raw.getD();

            infLimitF = new BigInteger[d + 1];
            supLimitF = new BigInteger[d + 1];

            for (int j = 0; j <= d; j++) {
                BigDecimal factor = e.pow(j).multiply(n);
                infLimitF[j] = alpha.multiply(factor).setScale(0, RoundingMode.FLOOR).toBigInteger();
                supLimitF[j] = beta.multiply(factor).setScale(0, RoundingMode.CEILING).toBigInteger();
            }
            infLimitF[d] = BigInteger.ONE;


            nBytesLength = n.toBigInteger().toByteArray().length;
        } else throw new InvalidKeyException("The key used is not a FOPE Key");
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
            output = new byte[nBytesLength];
        } else if (opmode == Cipher.DECRYPT_MODE) {
            output = new byte[Long.BYTES];
        }
        engineUpdate(input, inputOffset, inputLen, output, 0);
        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (opmode == Cipher.ENCRYPT_MODE) {
            long x = ByteBuffer.wrap(input).getLong();

            BigInteger cipher = f(0, 0);
            for (int j = 1; j <= d; j++) {
                int xI = (int) ((x >> (d - j)) & 1);
                cipher = BigInteger.valueOf(2 * xI - 1).multiply(f(j, x)).add(cipher);
            }

            byte[] cipherArray = cipher.toByteArray();
            System.arraycopy(cipherArray, 0, output, output.length - cipherArray.length, cipherArray.length);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            BigInteger c = new BigInteger(input);

            BigInteger a = f(0, 0);
            long x = c.compareTo(a) < 0 ? 0 : 1L << (d - 1);

            for (int j = 2; j <= d; j++) {
                int xI = (int) ((x >> (d - j + 1)) & 1);
                a = BigInteger.valueOf(2 * xI - 1).multiply(f(j - 1, x)).add(a);
                if (c.compareTo(a) >= 0) {
                    x |= 1L << (d - j);
                }
            }

            long x0 = x & 1;
            a = BigInteger.valueOf(2 * x0 - 1).multiply(f(d, x)).add(a);

            if (c.compareTo(a) != 0) x = Long.MIN_VALUE; // Maybe remove if Mondrian does change encrypted values

            System.arraycopy(ByteBuffer.allocate(Long.BYTES).putLong(x).array(), 0, output, 0, output.length);
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

    private BigInteger f(int i, long x) {
        try {
            // Include only i most significant bits
            int shift = d - i;
            x = x >> shift << shift;

            // Calculate hash
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(k);
            md.update(ByteBuffer.allocate(Long.BYTES).putLong(x).array());

            BigInteger bi = new BigInteger(md.digest());
            return bi.mod(supLimitF[i].subtract(infLimitF[i])).add(infLimitF[i]);
        } catch (NoSuchAlgorithmException | ArithmeticException e) {
            e.printStackTrace();
            return BigInteger.ONE.multiply(BigInteger.valueOf(-1));
        }
    }

}
