package crypto.algorithm.ope.acnf;

import crypto.EngineAutoBindable;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class ACNFKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();

    private byte l = ACNFAlgorithmParameterSpec.DEFAULT_L;

    @Override
    public String getBind() {
        return "KeyGenerator." + ACNFCipher.ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof ACNFAlgorithmParameterSpec))
            throw new InvalidAlgorithmParameterException();
        this.l = ((ACNFAlgorithmParameterSpec) algorithmParameterSpec).getL();
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int size, SecureRandom secureRandom) {
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        byte[] seed = secureRandom.generateSeed(31);
        return new ACNFSecretKeySpec.Raw().setL(l).setSeed(seed).build();
    }

}
