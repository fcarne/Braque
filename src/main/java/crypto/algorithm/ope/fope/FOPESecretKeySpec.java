package crypto.algorithm.ope.fope;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

public class FOPESecretKeySpec extends SecretKeySpec {
    public FOPESecretKeySpec(byte[] key) {
        super(key, "FOPE");
    }

    public FOPESecretKeySpec(Raw raw) {
        this(raw.encode());
    }

    public Raw decodeKey() {
        ByteBuffer buffer = ByteBuffer.wrap(getEncoded());
        if (buffer.remaining() != (2 * Long.BYTES + 2 * Double.BYTES)) return null;

        return new Raw().setN(buffer.getLong()).setAlpha(buffer.getDouble()).setE(buffer.getDouble()).setK(buffer.getLong());

    }

    public static class Raw {
        private long n;
        private double alpha;
        private double e;
        private long k;

        public Raw setN(long n) {
            this.n = n;
            return this;
        }

        public Raw setAlpha(double alpha) {
            this.alpha = alpha;
            return this;
        }

        public Raw setE(double e) {
            this.e = e;
            return this;
        }

        public Raw setK(long k) {
            this.k = k;
            return this;
        }

        public long getN() {
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

        public long getK() {
            return k;
        }

        public byte[] encode() {
            ByteBuffer buffer = ByteBuffer.allocate(2 * Long.BYTES + 2 * Double.BYTES);

            buffer.putLong(n);
            buffer.putDouble(alpha);
            buffer.putDouble(e);
            buffer.putLong(k);

            return buffer.array();
        }

        public FOPESecretKeySpec build() {
            return new FOPESecretKeySpec(this);
        }
    }

}
