package crypto.algorithm.ope.piore;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

public class PIORESecretKeySpec extends SecretKeySpec {
    public PIORESecretKeySpec(byte[] key) {
        super(key, PIORECipher.ALGORITHM_NAME);
    }

    public PIORESecretKeySpec(Raw raw) {
        this(raw.encode());
    }

    public Raw decodeKey() {
        ByteBuffer buffer = ByteBuffer.wrap(getEncoded());
        byte[] k = new byte[30];
        buffer.get(k);
        byte m = buffer.get();
        byte n = buffer.get();

        return new Raw().setK(k).setM(m).setN(n);
    }

    public static class Raw {

        private byte[] k;
        private byte m;
        private byte n;

        public byte[] getK() {
            return k;
        }

        public Raw setK(byte[] k) {
            this.k = k;
            return this;
        }

        public byte getM() {
            return m;
        }

        public Raw setM(byte m) {
            this.m = m;
            return this;
        }

        public byte getN() {
            return n;
        }

        public Raw setN(byte n) {
            this.n = n;
            return this;
        }

        public byte[] encode() {
            ByteBuffer buffer = ByteBuffer.allocate(k.length + 2 * Byte.BYTES);
            buffer.put(k).put(m).put(n);
            return buffer.array();
        }

        public PIORESecretKeySpec build() {
            return new PIORESecretKeySpec(this);
        }
    }

}
