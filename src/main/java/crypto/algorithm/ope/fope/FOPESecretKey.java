package crypto.algorithm.ope.fope;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

public class FOPESecretKey implements SecretKey {

    public static final int MINIMUM_KEY_SIZE = 32;
    public static final int MAXIMUM_KEY_SIZE = 64;

    public static final int FIXED_LENGTH = Double.BYTES * 3 + Byte.BYTES;

    private final byte[] encoded;

    private final double n;
    private final double alpha;
    private final double e;
    private final byte d;
    private final byte[] k;

    public FOPESecretKey(double n, double alpha, double e, byte d, byte[] k) throws InvalidKeyException {
        if (isKeyNotValid(n, alpha, e, d))
            throw new InvalidKeyException(getInvalidParameters(n, alpha, e, d));
        if (isKeySizeNotValid(FIXED_LENGTH + k.length))
            throw new InvalidKeyException(getKeySizeError(FIXED_LENGTH + k.length));

        this.n = n;
        this.alpha = alpha;
        this.e = e;
        this.d = d;
        this.k = k;

        ByteBuffer buffer = ByteBuffer.allocate(FIXED_LENGTH + k.length);
        buffer.putDouble(n).putDouble(alpha).putDouble(e).put(d).put(k);

        this.encoded = buffer.array();

    }

    public FOPESecretKey(byte[] encoded) throws InvalidKeyException {
        if (isKeySizeNotValid(encoded.length))
            throw new InvalidKeyException(getKeySizeError(encoded.length));

        ByteBuffer buffer = ByteBuffer.wrap(encoded);

        this.n = buffer.getDouble();
        this.alpha = buffer.getDouble();
        this.e = buffer.getDouble();
        this.d = buffer.get();

        if (isKeyNotValid(n, alpha, e, d))
            throw new InvalidKeyException(getInvalidParameters(n, alpha, e, d));

        this.k = new byte[buffer.remaining()];
        buffer.get(k);

        this.encoded = encoded.clone();
    }

    public double getN() {
        return n;
    }

    public double getAlpha() {
        return alpha;
    }

    public double getBeta() {
        return 1 - alpha;
    }

    public double getE() {
        return e;
    }

    public byte getD() {
        return d;
    }

    public byte[] getK() {
        return k;
    }

    @Override
    public String getAlgorithm() {
        return FOPECipher.ALGORITHM_NAME;
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

    public static boolean isKeyNotValid(double n, double alpha, double e, byte d) {
        return n < 0 || alpha < 0 || alpha > 0.5 || e < 0 || e > alpha || d < 0;
    }

    public static String getKeySizeError(int len) {
        return "Invalid key size: " + len * 8 + ". Key size can only range from " + MINIMUM_KEY_SIZE * 8 + " to " + MAXIMUM_KEY_SIZE * 8 +  " (inclusive)";
    }

    public static String getInvalidParameters(double n, double alpha, double e, byte d) {
        StringBuilder error = new StringBuilder().append("Invalid parameters:\n");
        if (n < 0) error.append(" - n must be greater than 0").append("\n");
        if (alpha < 0 || alpha > 0.5) error.append(" - alpha must be between 0.0 and 0.5").append("\n");
        if (e < 0 || e > alpha) error.append(" - e must be between 0.0 and alpha").append("\n");
        if (d < 0) error.append(" - d must be greater than 0").append("\n");

        return error.toString();
    }
}
