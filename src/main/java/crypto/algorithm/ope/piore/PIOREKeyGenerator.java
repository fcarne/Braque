package crypto.algorithm.ope.piore;

import crypto.EngineAutoBindable;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class PIOREKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();
    private PIOREAlgorithmParameterSpec parameterSpec = new PIOREAlgorithmParameterSpec();

    @Override
    public String getBind() {
        return "KeyGenerator." + PIORECipher.ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof PIOREAlgorithmParameterSpec))
            throw new InvalidAlgorithmParameterException();
        parameterSpec = (PIOREAlgorithmParameterSpec) algorithmParameterSpec;
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int keySize, SecureRandom secureRandom) {
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        byte[] k = new byte[30];
        secureRandom.nextBytes(k);

        byte m = (byte) (secureRandom.nextInt(24 - 12) + 12);

        return new PIORESecretKeySpec.Raw().setK(k).setM(m).setN(parameterSpec.getN()).build();
    }

}
