package crypto.algorithm.ope.piore;

import crypto.algorithm.GaloisCipher;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;

public class PIORECipher extends GaloisCipher {

    public static final String ALGORITHM_NAME = "PIOre";
    private static final String PRF_ALGORITHM = "HmacSha256";

    private final Mac mac;

    private BigInteger m;
    private byte n;

    private int mPowerNBytesLength;

    public PIORECipher() throws NoSuchAlgorithmException {
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
        PIORESecretKey pioreKey = new PIORESecretKey(keyBytes);

        m = BigInteger.TWO.pow(pioreKey.getM());
        n = pioreKey.getN();

        mac.init(new SecretKeySpec(pioreKey.getK(), PRF_ALGORITHM));
        mPowerNBytesLength = m.pow(n).toByteArray().length;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (opMode == Cipher.ENCRYPT_MODE && mPowerNBytesLength > 0) {
            return mPowerNBytesLength;
        } else if (opMode == Cipher.DECRYPT_MODE) {
            return Long.BYTES;
        } else return 0;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (opMode == Cipher.ENCRYPT_MODE) {
            long b = ByteBuffer.wrap(input).getLong();

            BigInteger cipher = BigInteger.ZERO;
            for (int i = 1; i <= n; i++) {
                BigInteger uI = f(i, b);
                cipher = m.pow(n - i).multiply(uI).add(cipher);
            }

            byte[] cipherArray = cipher.toByteArray();
            System.arraycopy(cipherArray, 0, output, output.length - cipherArray.length, cipherArray.length);
        } else if (opMode == Cipher.DECRYPT_MODE) {
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

    private BigInteger f(int i, long b) {
        int shift = n - i + 1;
        int bI = (int) ((b >> (n - i)) & 1);
        b = b >> shift << shift;

        return prf(i, b).add(BigInteger.valueOf(bI)).mod(m);
    }

    private BigInteger prf(int i, long b) {
        byte[] message = ByteBuffer.allocate(Integer.BYTES + Long.BYTES).putInt(i).putLong(b).array();
        try {
            Mac macClone = (Mac) mac.clone();
            return new BigInteger(macClone.doFinal(message));
        } catch (CloneNotSupportedException e) {
            // never thrown
            throw new ProviderException(e);
        }

    }
}
