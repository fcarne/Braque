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

    private ACNFAlgorithmParameterSpec parameterSpec = new ACNFAlgorithmParameterSpec();

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
        parameterSpec = (ACNFAlgorithmParameterSpec) algorithmParameterSpec;
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int size, SecureRandom secureRandom) {
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        byte[] seed = secureRandom.generateSeed(30);
        return new ACNFSecretKeySpec.Raw().setL(parameterSpec.getL()).setN(parameterSpec.getN()).setSeed(seed).build();
    }

}
