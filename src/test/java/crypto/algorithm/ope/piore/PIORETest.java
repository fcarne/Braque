package crypto.algorithm.ope.piore;

import crypto.algorithm.ope.OPETest;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.Base64;

public class PIORETest extends OPETest {

    @Override
    public void setAlgorithmName() {
        algorithmName = PIORECipher.ALGORITHM_NAME;
    }

    @Override
    protected SecretKey buildCustomKey() throws InvalidKeyException {
        return new PIORESecretKey((byte) 16, (byte) 8, new byte[30]);
    }

    @Override
    protected SecretKey buildBase64Key() throws InvalidKeyException {
        return new PIORESecretKey(Base64.getDecoder().decode("JTbfxrghvc2TDIR6/Bp/yGugI5kD2F8xMB3PLZ/iEwg="));
    }
}
