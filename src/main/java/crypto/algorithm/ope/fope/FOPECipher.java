package crypto.algorithm.ope.fope;

import crypto.algorithm.GaloisCipher;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.security.*;

public class FOPECipher extends GaloisCipher {

    public static final String ALGORITHM_NAME = "FastOPE";
    private static final String PRF_ALGORITHM = "HmacSha256";
    private byte d;

    private BigInteger[] infLimitF;
    private BigInteger[] supLimitF;
    private final Mac mac;
    private int nBytesLength;

    public FOPECipher() throws NoSuchAlgorithmException {
        mac = Mac.getInstance(PRF_ALGORITHM);
    }

    @Override
    public String getBind() {
        return "Cipher." + ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(int opMode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        this.opMode = opMode;
        byte[] keyBytes = getKeyBytes(key);
        FOPESecretKey fopeKey = new FOPESecretKey(keyBytes);

        BigDecimal alpha = BigDecimal.valueOf(fopeKey.getAlpha());
        BigDecimal beta = BigDecimal.valueOf(fopeKey.getBeta());
        BigDecimal n = BigDecimal.valueOf((fopeKey.getN()));
        BigDecimal e = BigDecimal.valueOf(fopeKey.getE());

        d = fopeKey.getD();
        infLimitF = new BigInteger[d + 1];
        supLimitF = new BigInteger[d + 1];

        for (int j = 0; j <= d; j++) {
            BigDecimal factor = e.pow(j).multiply(n);
            infLimitF[j] = alpha.multiply(factor).setScale(0, RoundingMode.FLOOR).toBigInteger();
            supLimitF[j] = beta.multiply(factor).setScale(0, RoundingMode.CEILING).toBigInteger();
        }
        infLimitF[d] = BigInteger.ONE;

        mac.init(new SecretKeySpec(fopeKey.getK(), PRF_ALGORITHM));
        nBytesLength = n.toBigInteger().toByteArray().length;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (opMode == Cipher.ENCRYPT_MODE && nBytesLength > 0) {
            return nBytesLength;
        } else if (opMode == Cipher.DECRYPT_MODE) {
            return Long.BYTES;
        } else return 0;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (opMode == Cipher.ENCRYPT_MODE) {
            long x = ByteBuffer.wrap(input).getLong();

            BigInteger cipher = f(0, 0);
            for (int i = 1; i <= d; i++) {
                int xI = (int) ((x >> (d - i)) & 1);
                cipher = BigInteger.valueOf(2 * xI - 1).multiply(f(i, x)).add(cipher);
            }

            byte[] cipherArray = cipher.toByteArray();
            System.arraycopy(cipherArray, 0, output, output.length - cipherArray.length, cipherArray.length);
        } else if (opMode == Cipher.DECRYPT_MODE) {
            BigInteger c = new BigInteger(input);

            BigInteger a = f(0, 0);
            long x = c.compareTo(a) < 0 ? 0 : 1L << (d - 1);

            for (int i = 2; i <= d; i++) {
                int xI = (int) ((x >> (d - i + 1)) & 1);
                a = BigInteger.valueOf(2 * xI - 1).multiply(f(i - 1, x)).add(a);
                if (c.compareTo(a) >= 0) {
                    x |= 1L << (d - i);
                }
            }

            long x0 = x & 1;
            a = BigInteger.valueOf(2 * x0 - 1).multiply(f(d, x)).add(a);

            if (c.compareTo(a) != 0) x = Long.MIN_VALUE; // Maybe remove if Mondrian does change encrypted values

            System.arraycopy(ByteBuffer.allocate(Long.BYTES).putLong(x).array(), 0, output, 0, output.length);
        }

        return inputLen;
    }

    private BigInteger f(int i, long x) {
        try {
            // Include only i most significant bits
            int shift = d - i;
            x = x >> shift << shift;

            return prf(x).mod(supLimitF[i].subtract(infLimitF[i])).add(infLimitF[i]);
        } catch (ArithmeticException e) {
            e.printStackTrace();
            return BigInteger.ONE.multiply(BigInteger.valueOf(-1));
        }
    }

    /*private BigInteger prf_NewForEach(long x) {
        byte[] message = ByteBuffer.allocate(Long.BYTES).putLong(x).array();

        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(k, "HmacSHA256"));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new ProviderException(e);
        }
        byte[] hash = mac.doFinal(message);
        return new BigInteger(hash);
    }*/

    /*private BigInteger prf_OneForInstance(long x) {
        byte[] message = ByteBuffer.allocate(Long.BYTES).putLong(x).array();
        byte[] hash;
        synchronized (mac) {
            hash = mac.doFinal(message);
        }
        return new BigInteger(hash);
    }*/

    private BigInteger prf(long x) {
        byte[] message = ByteBuffer.allocate(Long.BYTES).putLong(x).array();
        try {
            Mac macClone = (Mac) mac.clone();
            return new BigInteger(macClone.doFinal(message));
        } catch (CloneNotSupportedException e) {
            // never thrown
            throw new ProviderException(e);
        }

    }

}
