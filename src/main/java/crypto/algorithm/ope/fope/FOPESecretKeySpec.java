package crypto.algorithm.ope.fope;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

public class FOPESecretKeySpec extends SecretKeySpec {
    public FOPESecretKeySpec(byte[] key) {
        super(key, FOPECipher.ALGORITHM_NAME);
    }

    public FOPESecretKeySpec(Raw raw) {
        this(raw.encode());
    }

    public Raw decodeKey() {
        ByteBuffer buffer = ByteBuffer.wrap(getEncoded());
        if (buffer.remaining() != (3 * Double.BYTES + Long.BYTES)) return null;

        return new Raw().setN(buffer.getDouble()).setAlpha(buffer.getDouble()).setE(buffer.getDouble()).setK(buffer.getLong());

    }

    public static class Raw {
        private double n;
        private double alpha;
        private double e;
        private long k;

        public Raw setN(double n) {
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

        public long getK() {
            return k;
        }

        public byte[] encode() {
            ByteBuffer buffer = ByteBuffer.allocate(3 * Double.BYTES + Long.BYTES);

            buffer.putDouble(n);
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
