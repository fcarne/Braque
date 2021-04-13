package crypto.algorithm.ope;

import crypto.algorithm.GaloisTest;
import org.junit.jupiter.api.RepeatedTest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

import static org.junit.jupiter.api.Assertions.*;

public abstract class OPETest extends GaloisTest {

    @Override
    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public void decryptedEqualsOriginal() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        long x = random.nextInt(255);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x).array());

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = c.doFinal(encrypted);

        assertEquals(x, ByteBuffer.wrap(decrypted).getLong());
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public void encryptedOrderRespectsOriginal() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        long x1 = random.nextInt(255);
        long x2 = random.nextInt(255);

        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted1 = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x1).array());
        byte[] encrypted2 = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x2).array());

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted1 = c.doFinal(encrypted1);
        byte[] decrypted2 = c.doFinal(encrypted2);


        assertAll(
                () -> assertEquals(x1, ByteBuffer.wrap(decrypted1).getLong()),
                () -> assertEquals(x2, ByteBuffer.wrap(decrypted2).getLong()),
                () -> {
                    int i = new BigInteger(encrypted1).compareTo(new BigInteger(encrypted2));
                    if (x1 < x2) {
                        assertTrue(i < 0);
                    } else if (x1 > x2) {
                        assertTrue(i > 0);
                    } else {
                        assertEquals(i, 0);
                    }
                });
    }
}
