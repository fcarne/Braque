package crypto.algorithm.ope.tym;

import crypto.algorithm.ope.OPETest;

import javax.crypto.SecretKey;

public class TYMTest extends OPETest {

    @Override
    public void setAlgorithmName() {
        algorithmName = TYMCipher.ALGORITHM_NAME;
    }

    @Override
    protected SecretKey buildCustomKey() {
        return new TYMSecretKeySpec.Raw().setK(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
                .setA(-4097).setM(256).setIntervalM(new TYMInterval(360285, 4342)).build();
    }
}
