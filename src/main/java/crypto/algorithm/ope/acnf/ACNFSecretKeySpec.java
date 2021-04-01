package crypto.algorithm.ope.acnf;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

public class ACNFSecretKeySpec extends SecretKeySpec {

    public static final int DEFAULT_SIZE = 256;

    public ACNFSecretKeySpec(byte[] key) {
        super(key, ACNFCipher.ALGORITHM_NAME);
    }

    public ACNFSecretKeySpec(Raw raw) {
        this(raw.encode());
    }

    public Raw decodeKey() throws InvalidKeyException {
        ByteBuffer buffer = ByteBuffer.wrap(getEncoded());
        int size = buffer.remaining() * 8;

        if (size % DEFAULT_SIZE != 0) throw new InvalidKeyException();

        byte l = buffer.get();
        byte c = buffer.get();

        byte[] a = new byte[10];
        for (int i = 0; i < 10; i++) {
            a[i] = buffer.get();
        }

        int ratiosLength = getRatiosLength(size);

        short[] p = new short[ratiosLength];
        short[] q = new short[ratiosLength];

        for (int i = 0; i < ratiosLength; i++) {
            p[i] = buffer.getShort();
            q[i] = buffer.getShort();
        }
        return new Raw(size).setL(l).setC(c).setA(a).setP(p).setQ(q);
    }

    public static class Raw {

        byte l;
        byte c;
        short[] p;
        short[] q;
        byte[] a = new byte[10];

        public Raw(int size) throws InvalidKeyException {
            if (size <= 0 || size % DEFAULT_SIZE != 0)
                throw new InvalidKeyException("Key size must be a multiple of 256");

            int ratiosLength = getRatiosLength(size);

            p = new short[ratiosLength];
            q = new short[ratiosLength];
        }

        public byte getL() {
            return l;
        }

        public Raw setL(byte l) {
            this.l = l;
            return this;
        }

        public byte getC() {
            return c;
        }

        public Raw setC(byte c) {
            this.c = c;
            return this;
        }

        public short[] getP() {
            return p;
        }

        public Raw setP(short[] p) {
            this.p = p;
            return this;

        }

        public short[] getQ() {
            return q;
        }

        public Raw setQ(short[] q) {
            this.q = q;
            return this;

        }

        public byte[] getA() {
            return a;
        }

        public Raw setA(byte[] a) {
            this.a = a;
            return this;
        }

        public byte[] encode() {
            ByteBuffer buffer = ByteBuffer.allocate(Short.BYTES * (p.length + q.length) + Byte.BYTES * 12);

            System.out.println(buffer.remaining());
            System.out.println(p.length);

            buffer.put(l);
            buffer.put(c);

            for (byte b : a) {
                buffer.put(b);
            }

            for (int i = 0; i < p.length; i++) {
                buffer.putShort(p[i]).putShort(q[i]);
            }

            return buffer.array();
        }

        public ACNFSecretKeySpec build() {
            return new ACNFSecretKeySpec(this);
        }
    }

    public static int getRatiosLength(int size) {
        return (size / 8 - Byte.BYTES * 12) / (2 * Short.BYTES);
    }

}
