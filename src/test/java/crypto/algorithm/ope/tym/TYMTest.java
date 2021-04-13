package crypto.algorithm.ope.tym;

import crypto.algorithm.ope.OPETest;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.Base64;

public class TYMTest extends OPETest {

    @Override
    public void setAlgorithmName() {
        algorithmName = TYMCipher.ALGORITHM_NAME;
    }

    @Override
    protected SecretKey buildCustomKey() throws InvalidKeyException {
        return new TYMSecretKey(-4097, 256, new TYMInterval(360285, 4342), new byte[16]);
    }

    @Override
    protected SecretKey buildBase64Key() throws InvalidKeyException {
        return new TYMSecretKey(Base64.getDecoder().decode("///v/wAAAQAADfuCAAAQ5YKaavTzE4tlEkI494fw/HE="));
    }
}
