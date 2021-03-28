import crypto.BraqueProvider;
import crypto.algorithm.ope.fope.FOPEAlgorithmParameterSpec;
import crypto.algorithm.ope.fope.FOPESecretKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

public class FOPETest {

    SecretKey key;
    Cipher c;

    @BeforeAll
    static void addProvider() {
        BraqueProvider.add();
    }

    @BeforeEach
    public void setup() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        FOPEAlgorithmParameterSpec spec = new FOPEAlgorithmParameterSpec(16, 16);

        KeyGenerator keyGen = KeyGenerator.getInstance("FOPE");
        keyGen.init(spec);

        key = keyGen.generateKey();
        c = Cipher.getInstance("FOPE");
        c.init(Cipher.ENCRYPT_MODE, key, spec);
    }

    @Test
    public void decryptedEqualsOriginal() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        long x = new Random().nextInt(60000);

        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x).array());

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = c.doFinal(encrypted);

        assertEquals(x, ByteBuffer.wrap(decrypted).getLong());
    }

    @Test
    public void encryptedOrderRespectsOriginal() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        long x = new Random().nextInt(60000);

        c.init(Cipher.ENCRYPT_MODE, key);

        ByteBuffer values = ByteBuffer.allocate(3 * Long.BYTES).putLong(x).putLong(x + 100).putLong(x - 1000);
        values.position(0);
        byte[] encrypted = c.doFinal(values.array());

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = c.doFinal(encrypted);

        ByteBuffer decBuffer = ByteBuffer.wrap(decrypted);
        ByteBuffer encBuffer = ByteBuffer.wrap(encrypted);

        assertAll(
                () -> assertEquals(values.getLong(0), decBuffer.getLong(0)),
                () -> assertEquals(values.getLong(Long.BYTES), decBuffer.getLong(Long.BYTES)),
                () -> assertEquals(values.getLong(2 * Long.BYTES), decBuffer.getLong(2 * Long.BYTES)),
                () -> assertTrue(values.getLong(0) < values.getLong(Long.BYTES)),
                () -> assertTrue(values.getLong(0) > values.getLong(2 * Long.BYTES)),
                () -> assertTrue(encBuffer.getLong(0) < encBuffer.getLong(Long.BYTES)),
                () -> assertTrue(encBuffer.getLong(0) > encBuffer.getLong(2 * Long.BYTES))
        );
    }

    @Test
    public void customKey() throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        key = new FOPESecretKeySpec.Raw().setN((long) Math.ceil(16 / (0.85 * Math.pow(0.075, 16))))
                .setAlpha(0.15)
                .setE(0.075)
                .setK(Long.MAX_VALUE).build();

        long x = new Random().nextInt(60000);

        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x).array());

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = c.doFinal(encrypted);

        assertEquals(x, ByteBuffer.wrap(decrypted).getLong());


    }
}
