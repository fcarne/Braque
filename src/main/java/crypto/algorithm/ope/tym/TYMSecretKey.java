package crypto.algorithm.ope.tym;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

public class TYMSecretKey implements SecretKey {

    public static final int MINIMUM_KEY_SIZE = 32;
    public static final int MAXIMUM_KEY_SIZE = 64;

    public static final int FIXED_LENGTH = 2 * Integer.BYTES + TYMInterval.BYTES;

    private final byte[] encoded;

    private final int a;
    private final int m;
    private final TYMInterval intervalM;
    private final byte[] k;

    public TYMSecretKey(int a, int m, TYMInterval intervalM, byte[] k) throws InvalidKeyException {
        if (isKeyNotValid(a, m, intervalM))
            throw new InvalidKeyException(getInvalidParameters(a, m, intervalM));
        if (isKeySizeNotValid(FIXED_LENGTH + k.length))
            throw new InvalidKeyException(getKeySizeError(FIXED_LENGTH + k.length));

        this.a = a;
        this.m = m;
        this.intervalM = intervalM;
        this.k = k;

        ByteBuffer buffer = ByteBuffer.allocate(FIXED_LENGTH + k.length);
        buffer.putInt(a).putInt(m).put(intervalM.toByteArray()).put(k);

        this.encoded = buffer.array();

    }

    public TYMSecretKey(byte[] encoded) throws InvalidKeyException {
        if (isKeySizeNotValid(encoded.length))
            throw new InvalidKeyException(getKeySizeError(encoded.length));

        ByteBuffer buffer = ByteBuffer.wrap(encoded);

        this.a = buffer.getInt();
        this.m = buffer.getInt();

        byte[] intervalBytes = new byte[TYMInterval.BYTES];
        buffer.get(intervalBytes);
        this.intervalM = TYMInterval.fromByteArray(intervalBytes);

        if (isKeyNotValid(a, m, intervalM))
            throw new InvalidKeyException(getInvalidParameters(a, m, intervalM));

        this.k = new byte[buffer.remaining()];
        buffer.get(k);

        this.encoded = encoded.clone();
    }

    public int getA() {
        return a;
    }

    public int getM() {
        return m;
    }

    public TYMInterval getIntervalM() {
        return intervalM;
    }

    public byte[] getK() {
        return k;
    }

    @Override
    public String getAlgorithm() {
        return TYMCipher.ALGORITHM_NAME;
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

    public static boolean isKeyNotValid(int a, int m, TYMInterval intervalM) {
        return a > -1 || m < 0 || intervalM.c0 < intervalM.c1;
    }

    public static String getKeySizeError(int len) {
        return "Invalid key size: " + len * 8 + ". Key size can only range from " + MINIMUM_KEY_SIZE * 8 + " to " + MAXIMUM_KEY_SIZE * 8 +  " (inclusive)";
    }

    public static String getInvalidParameters(int a, int m, TYMInterval intervalM) {
        StringBuilder error = new StringBuilder().append("Invalid parameters:\n");
        if (a > -1) error.append(" - a must be less than -1").append("\n");
        if (m < 0) error.append(" - m must be greater than 0").append("\n");
        if (intervalM.c0 < intervalM.c1) error.append(" - c0 must be greater than c1").append("\n");

        return error.toString();
    }
}


