package crypto.algorithm.ope.aicd;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.InvalidKeyException;

public class AICDSecretKey implements SecretKey {

    public static final int MINIMUM_KEY_SIZE = 16;
    public static final int MAXIMUM_KEY_SIZE = 64;

    private final byte[] encoded;

    private final BigInteger k;

    public AICDSecretKey(BigInteger k) throws InvalidKeyException {
        if (isKeyNotValid(k))
            throw new InvalidKeyException(getInvalidParameters(k));

        byte[] kBytes = k.toByteArray();

        if (isKeySizeNotValid(kBytes.length))
            throw new InvalidKeyException(getKeySizeError(kBytes.length));

        this.k = k;
        this.encoded = kBytes;

    }

    public AICDSecretKey(byte[] encoded) throws InvalidKeyException {
        if (isKeySizeNotValid(encoded.length))
            throw new InvalidKeyException(getKeySizeError(encoded.length));

        this.k = new BigInteger(encoded);

        if (isKeyNotValid(k))
            throw new InvalidKeyException(getInvalidParameters(k));

        this.encoded = encoded.clone();
    }

    public BigInteger getK() {
        return k;
    }

    @Override
    public String getAlgorithm() {
        return AICDCipher.ALGORITHM_NAME;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }

    public static boolean isKeySizeNotValid(int len) {
        return len < MINIMUM_KEY_SIZE || len > MAXIMUM_KEY_SIZE;
    }

    public static boolean isKeyNotValid(BigInteger k) {
        return k.compareTo(BigInteger.ZERO) <= 0;
    }

    public static String getKeySizeError(int len) {
        return "Invalid key size: " + len * 8 + ". Key size can only range from " + MINIMUM_KEY_SIZE * 8 + " to " + MAXIMUM_KEY_SIZE * 8 +  " (inclusive)";
    }

    public static String getInvalidParameters(BigInteger k) {
        StringBuilder error = new StringBuilder().append("Invalid parameters:\n");
        if(k.compareTo(BigInteger.ZERO) <= 0) error.append(" - k must be positive");
        return error.toString();
    }
}

