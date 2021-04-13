package crypto.algorithm.ope.aicd;

import crypto.algorithm.GaloisCipher;

import javax.crypto.Cipher;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;

public class AICDCipher extends GaloisCipher {

    public static final String ALGORITHM_NAME = "CommonDivisor";

    private int opMode;
    private SecureRandom secureRandom;

    private BigInteger k;
    private BigInteger kPow;

    private int kBytesLength;


    @Override
    public String getBind() {
        return "Cipher." + ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(int opMode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        this.opMode = opMode;
        this.secureRandom = secureRandom;
        byte[] keyBytes = getKeyBytes(key);
        AICDSecretKey aicdKey = new AICDSecretKey(keyBytes);

        k = aicdKey.getK();
        kPow = BigDecimal.valueOf(Math.pow(k.doubleValue(), 3.0 / 4)).toBigInteger();

        kBytesLength = k.toByteArray().length;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (opMode == Cipher.ENCRYPT_MODE && kBytesLength > 0) {
            return k.toByteArray().length + inputLen + 1;
        } else if (opMode == Cipher.DECRYPT_MODE) {
            return Long.BYTES;
        } else return 0;
    }


    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (opMode == Cipher.ENCRYPT_MODE) {
            long m = ByteBuffer.wrap(input).getLong();

            BigInteger r = new BigInteger(k.bitLength(), secureRandom).mod(k.subtract(BigInteger.TWO.multiply(kPow))).add(kPow);
            BigInteger c = BigInteger.valueOf(m).multiply(k).add(r);

            byte[] cipherArray = c.toByteArray();
            System.arraycopy(cipherArray, 0, output, output.length - cipherArray.length, cipherArray.length);
        } else if (opMode == Cipher.DECRYPT_MODE) {
            BigInteger c = new BigInteger(input);
            long m = c.divide(k).longValue();

            System.arraycopy(ByteBuffer.allocate(Long.BYTES).putLong(m).array(), 0, output, 0, output.length);
        }

        return inputLen;
    }

}
