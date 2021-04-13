package crypto.algorithm;

import crypto.GaloisJCE;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.TestInstance;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class GaloisTest {
    protected String algorithmName;
    protected SecretKey key;
    protected Cipher c;
    protected final Random random = new Random();

    @BeforeAll
    public void addProvider() {
        GaloisJCE.add();
        System.out.println(this.getClass().getCanonicalName());
    }

    @BeforeEach
    public void setup() throws NoSuchAlgorithmException, NoSuchPaddingException {
        setAlgorithmName();
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithmName);
        key = keyGen.generateKey();
        c = Cipher.getInstance(algorithmName);
    }

    public abstract void setAlgorithmName();

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public abstract void decryptedEqualsOriginal() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public void customKey() throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        key = buildCustomKey();
        decryptedEqualsOriginal();
    }

    protected abstract SecretKey buildCustomKey() throws InvalidKeyException;

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    public void base64Key() throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        key = buildBase64Key();
        decryptedEqualsOriginal();
    }

    protected abstract SecretKey buildBase64Key() throws InvalidKeyException;

}