package crypto.algorithm.ope.gacd;

import crypto.EngineAutoBindable;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class GACDKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();
    private GACDAlgorithmParameterSpec parameterSpec = new GACDAlgorithmParameterSpec();

    @Override
    public String getBind() {
        return "KeyGenerator." + GACDCipher.ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof GACDAlgorithmParameterSpec))
            throw new InvalidAlgorithmParameterException();
        parameterSpec = (GACDAlgorithmParameterSpec) algorithmParameterSpec;
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int i, SecureRandom secureRandom) {
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        int lambda = parameterSpec.getLambda();
        BigInteger k = new BigInteger(lambda, secureRandom).mod(BigInteger.TWO.pow(lambda + 1).subtract(BigInteger.TWO.pow(lambda))).add(BigInteger.TWO.pow(lambda));
        return new GACDSecretKeySpec.Raw().setK(k).build();
    }

}
