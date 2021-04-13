package crypto.algorithm.ope.fope;

import crypto.EngineAutoBindable;
import crypto.GaloisJCE;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.math.BigDecimal;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class FOPEKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = GaloisJCE.getRandom();
    private int keySize = FOPESecretKey.MINIMUM_KEY_SIZE;
    private FOPEParameterSpec parameterSpec = new FOPEParameterSpec();

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
        if (!(algorithmParameterSpec instanceof FOPEParameterSpec))
            throw new InvalidAlgorithmParameterException("algorithmParameterSpec must be of type " + FOPEParameterSpec.class.getName());

        parameterSpec = (FOPEParameterSpec) algorithmParameterSpec;
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int keySize, SecureRandom secureRandom) {
        if (keySize % 8 != 0 || FOPESecretKey.isKeySizeNotValid(keySize / 8))
            throw new InvalidParameterException(FOPESecretKey.getKeySizeError(keySize / 8));

        this.keySize = keySize / 8;
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        double alpha = 0.5 * secureRandom.nextDouble();
        double beta = 1.0 - alpha;
        double e = secureRandom.nextDouble() * alpha;
        double n = Math.ceil(parameterSpec.getTau()) / (beta * BigDecimal.valueOf(e).pow(parameterSpec.getD()).doubleValue());
        byte[] k = new byte[keySize - FOPESecretKey.FIXED_LENGTH];
        secureRandom.nextBytes(k);

        try {
            return new FOPESecretKey(n, alpha, e, parameterSpec.getD(), k);
        } catch (InvalidKeyException ex) {
            // never thrown
            throw new ProviderException(ex);
        }
    }

}
