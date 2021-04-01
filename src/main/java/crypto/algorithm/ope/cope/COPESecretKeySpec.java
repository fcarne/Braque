package crypto.algorithm.ope.cope;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

public class COPESecretKeySpec extends SecretKeySpec {
    public COPESecretKeySpec(byte[] key) {
        super(key, COPECipher.ALGORITHM_NAME);
    }

    public COPESecretKeySpec(Raw raw) {
        this(raw.encode());
    }

    public Raw decodeKey() {
        ByteBuffer buffer = ByteBuffer.wrap(getEncoded());

        double p = buffer.getDouble();
        byte[] seed = new byte[24];
        buffer.get(seed);
        return new Raw().setP(p).setSeed(seed);

    }

    public static class Raw {

        private double p;
        private byte[] seed = new byte[24];

        public double getP() {
            return p;
        }

        public Raw setP(double p) {
            this.p = p;
            return this;
        }

        public byte[] getSeed() {
            return seed;
        }

        public Raw setSeed(byte[] seed) {
            this.seed = seed;
            return this;
        }

        public byte[] encode() {
            ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES + seed.length);
            buffer.putDouble(p);
            buffer.put(seed);
            return buffer.array();
        }

        public COPESecretKeySpec build() {
            return new COPESecretKeySpec(this);
        }
    }

}
