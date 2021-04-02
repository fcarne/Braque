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

        double n = buffer.getDouble();
        double alpha = buffer.getDouble();
        double e = buffer.getDouble();
        byte[] k = new byte[7];
        buffer.get(k);
        byte d = buffer.get();

        return new Raw().setN(n).setAlpha(alpha).setE(e).setK(k).setD(d);
    }

    public static class Raw {
        private double n;
        private double alpha;
        private double e;
        private byte[] k = new byte[7];
        private byte d;

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

        public Raw setK(byte[] k) {
            this.k = k;
            return this;
        }

        public byte getD() {
            return d;
        }

        public Raw setD(byte d) {
            this.d = d;
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

        public byte[] getK() {
            return k;
        }

        public byte[] encode() {
            ByteBuffer buffer = ByteBuffer.allocate(3 * Double.BYTES + Byte.BYTES * 8);
            buffer.putDouble(n).putDouble(alpha).putDouble(e).put(k).put(d);
            return buffer.array();
        }

        public FOPESecretKeySpec build() {
            return new FOPESecretKeySpec(this);
        }
    }

}
