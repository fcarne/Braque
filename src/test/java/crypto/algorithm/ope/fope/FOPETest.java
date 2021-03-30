package crypto.algorithm.ope.fope;

import crypto.algorithm.ope.OPETest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class FOPETest extends OPETest {

    @Override
    public void setAlgorithmName() {
        algorithmName = FOPECipher.ALGORITHM_NAME;
    }

    @Override
    public void customKey() throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        key = new FOPESecretKeySpec.Raw().setN(Math.ceil(16 / (0.75 * Math.pow(0.25, 8))))
                .setAlpha(0.25)
                .setE(0.25)
                .setK(Long.MAX_VALUE).build();

        long x = new Random().nextInt(255);

        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x).array());

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = c.doFinal(encrypted);

        assertEquals(x, ByteBuffer.wrap(decrypted).getLong());

    }


}
