package crypto.algortihm.ope.fope;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

public class FOPESecretKeySpec extends SecretKeySpec {
    public FOPESecretKeySpec(byte[] key) {
        super(key, "FOPE");
    }

    public FOPESecretKeySpec(long n, double alpha, double e, long k) {
        this(encodeRaw(n, alpha, e, k));
    }

    private static byte[] encodeRaw(long n, double alpha, double e, long k) {
        ByteBuffer buffer = ByteBuffer.allocate(2 * Long.BYTES + 2 * Double.BYTES);

        buffer.putLong(n);
        buffer.putDouble(alpha);
        buffer.putDouble(e);
        buffer.putLong(k);

        return buffer.array();
    }

    public Map<String, Number> decodeKey() {
        ByteBuffer buffer = ByteBuffer.wrap(getEncoded());
        if (buffer.remaining() != (2 * Long.BYTES + 2 * Double.BYTES)) return null;

        HashMap<String, Number> map = new HashMap<>();

        map.put("n", buffer.getLong());
        double alpha = buffer.getDouble();
        map.put("alpha", alpha);
        map.put("beta", 1 - alpha);
        map.put("e", buffer.getDouble());
        map.put("k", buffer.getLong());

        return map;

    }

}
