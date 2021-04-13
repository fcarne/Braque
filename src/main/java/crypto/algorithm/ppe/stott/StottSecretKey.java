package crypto.algorithm.ppe.stott;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

public class StottSecretKey implements SecretKey {

    public static final int MINIMUM_KEY_SIZE = 32;
    public static final int MAXIMUM_KEY_SIZE = 64;
    public static final String CIPHER_ALGORITHM = "AES";

    private final byte[] encoded;

    private final byte[] cipherKey;
    private final byte[] padSeed;

    public StottSecretKey(byte[] cipherKey, byte[] padSeed) throws InvalidKeyException {
        if (isKeyNotValid(cipherKey, padSeed))
            throw new InvalidKeyException(getInvalidParameters(cipherKey, padSeed));
        if (isKeySizeNotValid(cipherKey.length + padSeed.length))
            throw new InvalidKeyException(getKeySizeError(cipherKey.length + padSeed.length));

        this.cipherKey = cipherKey;
        this.padSeed = padSeed;

        ByteBuffer buffer = ByteBuffer.allocate(cipherKey.length + padSeed.length);
        buffer.put(cipherKey).put(padSeed);

        this.encoded = buffer.array();

    }

    public StottSecretKey(byte[] encoded) throws InvalidKeyException {
        if (isKeySizeNotValid(encoded.length))
            throw new InvalidKeyException(getKeySizeError(encoded.length));

        int cipherKeySize = getCipherKeySize(encoded.length);
        ByteBuffer buffer = ByteBuffer.wrap(encoded);

        this.cipherKey = new byte[cipherKeySize];
        this.padSeed = new byte[encoded.length - cipherKeySize];
        buffer.get(cipherKey).get(padSeed);

        this.encoded = encoded.clone();
    }

    public byte[] getCipherKey() {
        return cipherKey;
    }

    public byte[] getPadSeed() {
        return padSeed;
    }

    @Override
    public String getAlgorithm() {
        return StottCipher.ALGORITHM_NAME;
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

    public static boolean isKeyNotValid(byte[] cipherKey, byte[] padSeed) {
        return cipherKey.length > padSeed.length || getCipherKeySize(cipherKey.length + padSeed.length) != cipherKey.length;
    }

    public static String getKeySizeError(int len) {
        return "Invalid key size: " + len * 8 + ". Key size can only range from " + MINIMUM_KEY_SIZE * 8 + " to " + MAXIMUM_KEY_SIZE * 8 + " (inclusive)";
    }

    public static String getInvalidParameters(byte[] cipherKey, byte[] padSeed) {
        StringBuilder error = new StringBuilder().append("Invalid parameters:\n");
        if (cipherKey.length > padSeed.length || getCipherKeySize(cipherKey.length + padSeed.length) != cipherKey.length)
            error.append(" - cipherKey must be shorter than padSeed and must respect the size given by getCipherKeySize()").append("\n");

        return error.toString();
    }

    public static int getCipherKeySize(int len) {
        if (len == MAXIMUM_KEY_SIZE) return 32;
        else if (len >= 48) return 24;
        else if (len >= MINIMUM_KEY_SIZE) return 16;
        else return -1;

    }
}
