package crypto.algorithm.ope.aicd;

import crypto.algorithm.ope.OPETest;
import org.junit.jupiter.api.RepeatedTest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

public class AICDTest extends OPETest {

    @Override
    public void setAlgorithmName() {
        algorithmName = AICDCipher.ALGORITHM_NAME;
    }

    @Override
    protected SecretKey buildCustomKey() throws InvalidKeyException {
        return new AICDSecretKey(new BigInteger("88506266647602766350238521397384533217"));
    }

    @Override
    protected SecretKey buildBase64Key() throws InvalidKeyException {
        return new AICDSecretKey(Base64.getDecoder().decode("SwffGYVKIPZyr/HfJz7Atg=="));
    }

    @Override
    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public void encryptedOrderRespectsOriginal() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        long x1 = new Random().nextInt(255);
        long x2 = new Random().nextInt(255);

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
                        assertNotEquals(i, 0);
                    }
                });
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public void sameValueDifferentCiphertexts() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        long x = new Random().nextInt(255);

        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted1 = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x).array());
        byte[] encrypted2 = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x).array());

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted1 = c.doFinal(encrypted1);
        byte[] decrypted2 = c.doFinal(encrypted2);

        assertAll(
                () -> assertEquals(x, ByteBuffer.wrap(decrypted1).getLong()),
                () -> assertEquals(x, ByteBuffer.wrap(decrypted2).getLong()),
                () -> assertNotEquals(new BigInteger(encrypted1), new BigInteger(encrypted2)));
    }
}
