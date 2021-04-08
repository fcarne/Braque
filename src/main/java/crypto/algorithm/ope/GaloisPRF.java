package crypto.algorithm.ope;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class GaloisPRF {

    public static byte[] generate(byte[] key, long...params) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        md.update(key);
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES * params.length);
        Arrays.stream(params).forEach(buffer::putLong);
        buffer.rewind();
        md.update(buffer);

        return md.digest();
    }
}
