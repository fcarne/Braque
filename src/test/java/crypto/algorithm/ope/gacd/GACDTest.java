package crypto.algorithm.ope.gacd;

import crypto.algorithm.ope.OPETest;
import org.junit.jupiter.api.RepeatedTest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GACDTest extends OPETest {

    @Override
    public void setAlgorithmName() {
        algorithmName = GACDCipher.ALGORITHM_NAME;
    }

    @Override
    protected SecretKey buildCustomKey() {
        return new GACDSecretKeySpec.Raw().setK(new BigInteger("88506266647602766350238521397384533217")).build();
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public void sameValueDifferentCiphers() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
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
