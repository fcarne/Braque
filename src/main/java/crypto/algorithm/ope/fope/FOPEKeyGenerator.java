package crypto.algorithm.ope.fope;

import crypto.EngineAutoBindable;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.math.BigDecimal;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class FOPEKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();
    private int tau = FOPEAlgorithmParameterSpec.DEFAULT_TAU;
    private int d = FOPEAlgorithmParameterSpec.DEFAULT_D;

    @Override
    public String getBind() {
        return "KeyGenerator." + FOPECipher.ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof FOPEAlgorithmParameterSpec))
            throw new InvalidAlgorithmParameterException();
        tau = ((FOPEAlgorithmParameterSpec) algorithmParameterSpec).getTau();
        d = ((FOPEAlgorithmParameterSpec) algorithmParameterSpec).getD();
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int i, SecureRandom secureRandom) {
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        double alpha = 0.5 * secureRandom.nextDouble();
        double beta = 1.0 - alpha;
        double e = secureRandom.nextDouble() * alpha;
        double n = Math.ceil(tau / (beta * BigDecimal.valueOf(e).pow(d).doubleValue()));
        long k = secureRandom.nextLong();

        return new FOPESecretKeySpec.Raw().setN(n).setAlpha(alpha).setE(e).setK(k).build();
    }

}
