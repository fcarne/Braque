package crypto.algorithm.ope.cope;

import crypto.EngineAutoBindable;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class COPEKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();
    private long d = COPEAlgorithmParameterSpec.DEFAULT_D;

    @Override
    public String getBind() {
        return "KeyGenerator." + COPECipher.ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof COPEAlgorithmParameterSpec))
            throw new InvalidAlgorithmParameterException();
        this.d = ((COPEAlgorithmParameterSpec)algorithmParameterSpec).getD();
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int size, SecureRandom secureRandom) {
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        long p = secureRandom.nextLong() + d;
        byte[] seed = secureRandom.generateSeed(24);
        return new COPESecretKeySpec.Raw().setP(p).setSeed(seed).build();
    }

}
