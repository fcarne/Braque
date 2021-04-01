package crypto.algorithm.ope.fope;

import crypto.algorithm.ope.OPETest;

import javax.crypto.SecretKey;

public class FOPETest extends OPETest {

    @Override
    public void setAlgorithmName() {
        algorithmName = FOPECipher.ALGORITHM_NAME;
    }

    @Override
    protected SecretKey buildCustomKey() {
        return new FOPESecretKeySpec.Raw().setN(Math.ceil(16 / (0.75 * Math.pow(0.25, 8))))
                .setAlpha(0.25)
                .setE(0.25)
                .setK(Long.MAX_VALUE).build();
    }
}
