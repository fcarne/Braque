package crypto.algorithm.ope.fope;

import crypto.algorithm.ope.OPETest;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.Base64;

public class FOPETest extends OPETest {

    @Override
    public void setAlgorithmName() {
        algorithmName = FOPECipher.ALGORITHM_NAME;
    }

    @Override
    protected SecretKey buildCustomKey() throws InvalidKeyException {
        return new FOPESecretKey(Math.ceil(16 / (0.75 * Math.pow(0.25, 8))), 0.25, 0.25, (byte) 8, new byte[]{0, 0, 0, 0, 0, 0, 0});
    }

    @Override
    protected SecretKey buildBase64Key() throws InvalidKeyException {
        return new FOPESecretKey(Base64.getDecoder().decode("Qna1nFfLZow/tQZwVvInlD+l5DzCL5LwCEe4R+UhAhQ="));
    }
}
