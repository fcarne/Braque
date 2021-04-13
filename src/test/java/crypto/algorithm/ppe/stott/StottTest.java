package crypto.algorithm.ppe.stott;

import crypto.algorithm.ppe.PPETest;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.Base64;

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
}
