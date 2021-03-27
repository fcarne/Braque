package crypto.algortihm.ope.fope;

import crypto.EngineAutoBindable;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class FOPEKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom;
    private int tau;
    private int d;

    public FOPEKeyGenerator() {
        secureRandom = new SecureRandom();
        tau = FOPEAlgorithmParameterSpec.DEFAULT_TAU;
        d = FOPEAlgorithmParameterSpec.DEFAULT_D;
    }

    @Override
    public String getBind() {
        return "KeyGenerator.FOPE";
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof FOPEAlgorithmParameterSpec)) throw new InvalidAlgorithmParameterException();
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
        double alpha = 0.2 + 0.3 * secureRandom.nextDouble();
        double beta = 1.0 - alpha;
        double e = (1 + secureRandom.nextDouble()) * alpha / 2;
        long n = (long) Math.ceil((double) tau / (beta * Math.pow(e, d)));
        long k = secureRandom.nextLong() & Long.MAX_VALUE; // k can only be positive

        return new FOPESecretKeySpec(n, alpha, e, k);
    }

}
