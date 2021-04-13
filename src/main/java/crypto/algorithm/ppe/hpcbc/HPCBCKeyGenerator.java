package crypto.algorithm.ppe.hpcbc;

import crypto.EngineAutoBindable;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class HPCBCKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();
    private HPCBCParameterSpec parameterSpec = new HPCBCParameterSpec();

    @Override
    public String getBind() {
        return "KeyGenerator." + HPCBCCipher.ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof HPCBCParameterSpec))
            throw new InvalidAlgorithmParameterException();
        parameterSpec = (HPCBCParameterSpec) algorithmParameterSpec;
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int keySize, SecureRandom secureRandom) {
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        return new HPCBCSecretKey();
    }

}
