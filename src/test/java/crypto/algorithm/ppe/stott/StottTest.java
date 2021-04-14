package crypto.algorithm.ppe.stott;

import crypto.algorithm.ppe.PPETest;
import org.junit.jupiter.api.RepeatedTest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class StottTest extends PPETest {

    @Override
    public void setAlgorithmName() {
        algorithmName = StottCipher.ALGORITHM_NAME;
    }

    protected SecretKey buildCustomKey() throws InvalidKeyException {
        return new StottSecretKey(new byte[16], new byte[16]);
    }

    @Override
    protected SecretKey buildBase64Key() throws InvalidKeyException {
        return new StottSecretKey(Base64.getDecoder().decode("iF9aQ286q47oX8RMl9m5y/vLfwG4hw9DddOGnoADxgI="));
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public void ipV4() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnknownHostException {
        byte[] x = new byte[4];
        random.nextBytes(x);

        InetAddress address = InetAddress.getByAddress(x);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = c.doFinal(address.getAddress());

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = c.doFinal(encrypted);

        assertEquals(address, InetAddress.getByAddress(decrypted));
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public void ipV6() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnknownHostException {
        byte[] x = new byte[16];
        random.nextBytes(x);

        InetAddress address = InetAddress.getByAddress(x);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = c.doFinal(address.getAddress());

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = c.doFinal(encrypted);

        assertEquals(address, InetAddress.getByAddress(decrypted));
    }
}
