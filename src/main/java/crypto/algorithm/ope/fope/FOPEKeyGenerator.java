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
    private FOPEAlgorithmParameterSpec parameterSpec = new FOPEAlgorithmParameterSpec();

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
        parameterSpec = (FOPEAlgorithmParameterSpec) algorithmParameterSpec;
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
        double n = Math.ceil(parameterSpec.getTau()) / (beta * BigDecimal.valueOf(e).pow(parameterSpec.getD()).doubleValue());
        byte[] k = new byte[7];
        secureRandom.nextBytes(k);

        return new FOPESecretKeySpec.Raw().setN(n).setAlpha(alpha).setE(e).setK(k).setD(parameterSpec.getD()).build();
    }

}
