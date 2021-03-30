import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class Tests {

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException {
        byte[] seed = ByteBuffer.allocate(Long.BYTES).putLong(Long.MAX_VALUE).array();
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed(seed);
        SecureRandom random2 = SecureRandom.getInstance("SHA1PRNG", "SUN");
        random2.setSeed(seed);

        System.out.println(random.nextLong());
        System.out.println(random2.nextLong());
    }
}
