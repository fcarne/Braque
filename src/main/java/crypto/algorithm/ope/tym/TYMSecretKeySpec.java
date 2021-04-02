package crypto.algorithm.ope.tym;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

public class TYMSecretKeySpec extends SecretKeySpec {
    public TYMSecretKeySpec(byte[] key) {
        super(key, TYMCipher.ALGORITHM_NAME);
    }

    public TYMSecretKeySpec(Raw raw) {
        this(raw.encode());
    }

    public Raw decodeKey() {
        ByteBuffer buffer = ByteBuffer.wrap(getEncoded());

        byte[] k = new byte[Raw.LAMBDA / 8];
        buffer.get(k);
        int a = buffer.getInt();
        int m = buffer.getInt();
        TYMInterval intervalM = new TYMInterval(buffer.getDouble(), buffer.getDouble());

        return new Raw().setK(k).setA(a).setM(m).setIntervalM(intervalM);
    }

    public static class Raw {
        public static final int LAMBDA = 64;
        private byte[] k = new byte[LAMBDA / 8];
        private int a;
        private int m;
        private TYMInterval intervalM;

        public byte[] getK() {
            return k;
        }

        public Raw setK(byte[] k) {
            this.k = k;
            return this;
        }

        public int getA() {
            return a;
        }

        public Raw setA(int a) {
            this.a = a;
            return this;
        }

        public int getM() {
            return m;
        }

        public Raw setM(int m) {
            this.m = m;
            return this;

        }

        public TYMInterval getIntervalM() {
            return intervalM;
        }

        public Raw setIntervalM(TYMInterval intervalM) {
            this.intervalM = intervalM;
            return this;
        }

        public byte[] encode() {
            ByteBuffer buffer = ByteBuffer.allocate(2 * Double.BYTES + k.length + 2 * Integer.BYTES);
            buffer.put(k).putInt(a).putInt(m).putDouble(intervalM.inf).putDouble(intervalM.sup);
            return buffer.array();
        }

        public TYMSecretKeySpec build() {
            return new TYMSecretKeySpec(this);
        }
    }

}
