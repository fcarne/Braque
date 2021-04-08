package crypto.algorithm.ppe.cryptopan;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

public class CryptoPanSecretKeySpec extends SecretKeySpec {
    public CryptoPanSecretKeySpec(byte[] key) {
        super(key, CryptoPanCipher.ALGORITHM_NAME);
    }

    public CryptoPanSecretKeySpec(Raw raw) {
        this(raw.encode());
    }

    public Raw decodeKey() {
        ByteBuffer buffer = ByteBuffer.wrap(getEncoded());

        byte[] key = new byte[16];
        byte[] pad = new byte[16];

        buffer.get(key);
        buffer.get(pad);

        return new Raw().setKey(key).setPad(pad);
    }

    public static class Raw {

        private byte[] key;
        private byte[] pad;

        public byte[] getKey() {
            return key;
        }

        public Raw setKey(byte[] key) {
            this.key = key;
            return this;
        }

        public byte[] getPad() {
            return pad;
        }

        public Raw setPad(byte[] pad) {
            this.pad = pad;
            return this;
        }

        public byte[] encode() {
            ByteBuffer buffer = ByteBuffer.allocate(32 * Byte.BYTES);
            buffer.put(key).put(pad);
            return buffer.array();
        }

        public CryptoPanSecretKeySpec build() {
            return new CryptoPanSecretKeySpec(this);
        }
    }

}
