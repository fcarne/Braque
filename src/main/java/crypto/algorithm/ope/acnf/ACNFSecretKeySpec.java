package crypto.algorithm.ope.acnf;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

public class ACNFSecretKeySpec extends SecretKeySpec {

    public ACNFSecretKeySpec(byte[] key) {
        super(key, ACNFCipher.ALGORITHM_NAME);
    }

    public ACNFSecretKeySpec(Raw raw) {
        this(raw.encode());
    }

    public Raw decodeKey() {
        ByteBuffer buffer = ByteBuffer.wrap(getEncoded());

        byte l = buffer.get();
        byte n = buffer.get();
        byte[] seed = new byte[30];
        buffer.get(seed);

        return new Raw().setL(l).setN(n).setSeed(seed);
    }

    public static class Raw {

        private byte l;
        private byte n;
        private byte[] seed = new byte[31];

        public byte getL() {
            return l;
        }

        public Raw setL(byte l) {
            this.l = l;
            return this;
        }

        public byte getN() {
            return n;
        }

        public Raw setN(byte n) {
            this.n = n;
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
            ByteBuffer buffer = ByteBuffer.allocate(Byte.BYTES * 32);

            buffer.put(l);
            buffer.put(n);
            buffer.put(seed);

            return buffer.array();
        }

        public ACNFSecretKeySpec build() {
            return new ACNFSecretKeySpec(this);
        }
    }

}
