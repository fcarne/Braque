package crypto.algorithm.ope.piore;

import crypto.EngineAutoBindable;
import crypto.GaloisJCE;
import crypto.algorithm.ope.fope.FOPESecretKey;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class PIOREKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = GaloisJCE.getRandom();
    private int keySize = PIORESecretKey.MINIMUM_KEY_SIZE;
    private PIOREParameterSpec parameterSpec = new PIOREParameterSpec();

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
        if (!(algorithmParameterSpec instanceof PIOREParameterSpec))
            throw new InvalidAlgorithmParameterException("algorithmParameterSpec must be of type " + PIOREParameterSpec.class.getName());

        parameterSpec = (PIOREParameterSpec) algorithmParameterSpec;
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
        byte[] k = new byte[keySize - PIORESecretKey.FIXED_LENGTH];
        secureRandom.nextBytes(k);

        byte m = (byte) (secureRandom.nextInt(24 - 12) + 12);

        try {
            return new PIORESecretKey(m, parameterSpec.getN(), k);
        } catch (InvalidKeyException e) {
            // never thrown
            throw new ProviderException(e);
        }
    }

}
