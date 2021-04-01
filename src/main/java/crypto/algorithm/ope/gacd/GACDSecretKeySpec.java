package crypto.algorithm.ope.gacd;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;

public class GACDSecretKeySpec extends SecretKeySpec {
    public GACDSecretKeySpec(byte[] key) {
        super(key, GACDCipher.ALGORITHM_NAME);
    }

    public GACDSecretKeySpec(Raw raw) {
        this(raw.encode());
    }

    public Raw decodeKey() {
        return new Raw().setK(new BigInteger(getEncoded()));
    }

    public static class Raw {

        BigInteger k;

        public BigInteger getK() {
            return k;
        }

        public Raw setK(BigInteger k) {
            this.k = k;
            return this;
        }

        public byte[] encode() {
            return k.toByteArray();
        }

        public GACDSecretKeySpec build() {
            return new GACDSecretKeySpec(this);
        }
    }

}
