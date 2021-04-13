package crypto.algorithm.ope.piore;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

public class PIORESecretKey implements SecretKey {

    public static final int MINIMUM_KEY_SIZE = 32;
    public static final int MAXIMUM_KEY_SIZE = 64;

    public static final int FIXED_LENGTH = 2 + Byte.BYTES;

    private final byte[] encoded;

    private final byte m;
    private final byte n;
    private final byte[] k;

    public PIORESecretKey(byte m, byte n, byte[] k) throws InvalidKeyException {
        if (isKeyNotValid(m, n))
            throw new InvalidKeyException(getInvalidParameters(m, n));
        if (isKeySizeNotValid(FIXED_LENGTH + k.length))
            throw new InvalidKeyException(getKeySizeError(FIXED_LENGTH + k.length));

        this.m = m;
        this.n = n;
        this.k = k;

        ByteBuffer buffer = ByteBuffer.allocate(FIXED_LENGTH + k.length);
        buffer.put(m).put(n).put(k);

        this.encoded = buffer.array();

    }

    public PIORESecretKey(byte[] encoded) throws InvalidKeyException {
        if (isKeySizeNotValid(encoded.length))
            throw new InvalidKeyException(getKeySizeError(encoded.length));

        ByteBuffer buffer = ByteBuffer.wrap(encoded);

        this.m = buffer.get();
        this.n = buffer.get();

        if (isKeyNotValid(m, n))
            throw new InvalidKeyException(getInvalidParameters(m, n));

        this.k = new byte[buffer.remaining()];
        buffer.get(k);

        this.encoded = encoded.clone();
    }

    public byte getM() {
        return m;
    }

    public byte getN() {
        return n;
    }

    public byte[] getK() {
        return k;
    }

    @Override
    public String getAlgorithm() {
        return PIORECipher.ALGORITHM_NAME;
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

    public static boolean isKeyNotValid(byte m, byte n) {
        return m < 12 || n < 0;
    }

    public static String getKeySizeError(int len) {
        return "Invalid key size: " + len * 8 + ". Key size can only range from " + MINIMUM_KEY_SIZE * 8 + " to " + MAXIMUM_KEY_SIZE * 8 +  " (inclusive)";
    }

    public static String getInvalidParameters(byte m, byte n) {
        StringBuilder error = new StringBuilder().append("Invalid parameters:\n");
        if (m < 12) error.append(" - m must be greater than 12 in order to avoid collision").append("\n");
        if (n < 0) error.append(" - n must be greater than 0").append("\n");

        return error.toString();
    }
}