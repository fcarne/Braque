package crypto.algorithm.ppe;

import crypto.algorithm.GaloisTest;
import org.junit.jupiter.api.RepeatedTest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

public abstract class PPETest extends GaloisTest {

    @Override
    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public void decryptedEqualsOriginal() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] x = new byte[16];
        random.nextBytes(x);

        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = c.doFinal(x);

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = c.doFinal(encrypted);

        assertArrayEquals(x, decrypted);
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public void encryptedPrefixRespectsOriginal() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] prefix = new byte[new Random().nextInt(16)];
        random.nextBytes(prefix);

        byte[] x1 = new byte[16];
        random.nextBytes(x1);
        byte[] x2 = new byte[16];
        random.nextBytes(x2);

        System.arraycopy(prefix, 0, x1, 0, prefix.length);
        System.arraycopy(prefix, 0, x2, 0, prefix.length);

        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted1 = c.doFinal(x1);
        byte[] encrypted2 = c.doFinal(x2);

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted1 = c.doFinal(encrypted1);
        byte[] decrypted2 = c.doFinal(encrypted2);

        assertAll(
                () -> assertArrayEquals(x1, decrypted1),
                () -> assertArrayEquals(x2, decrypted2),
                () -> {
                    for (int i = 0; i < prefix.length; i++) {
                        assertEquals(encrypted1[i], encrypted2[i]);
                    }
                });
    }
}
