package crypto.algorithm.ope.piore;

import crypto.algorithm.ope.OPETest;

import javax.crypto.SecretKey;

public class PIORETest extends OPETest {

    @Override
    public void setAlgorithmName() {
        algorithmName = PIORECipher.ALGORITHM_NAME;
    }

    @Override
    protected SecretKey buildCustomKey() {
        return new PIORESecretKeySpec.Raw().setK(new byte[30]).setM((byte) 16).setN((byte) 8).build();
    }
}
