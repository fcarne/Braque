package crypto.algorithm.ope.aicd;

import crypto.EngineAutoBindable;
import crypto.GaloisJCE;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class AICDKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = GaloisJCE.getRandom();
    private AICDParameterSpec parameterSpec = new AICDParameterSpec();

    @Override
    public String getBind() {
        return "KeyGenerator." + AICDCipher.ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof AICDParameterSpec))
            throw new InvalidAlgorithmParameterException("algorithmParameterSpec must be of type " + AICDParameterSpec.class.getName());

        parameterSpec = (AICDParameterSpec) algorithmParameterSpec;
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int keySize, SecureRandom secureRandom) {
        throw new InvalidParameterException("KeySize must be set with AICDParameterSpec since it depends on Lambda");
    }

    @Override
    protected SecretKey engineGenerateKey() {
        int lambda = parameterSpec.getLambda();
        BigInteger k = new BigInteger(lambda, secureRandom).mod(BigInteger.TWO.pow(lambda + 1).subtract(BigInteger.TWO.pow(lambda)))
                .add(BigInteger.TWO.pow(lambda));

        try {
            return new AICDSecretKey(k);
        } catch (InvalidKeyException e) {
            // never thrown
            throw new ProviderException(e);
        }
    }

}
