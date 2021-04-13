package crypto.algorithm.ppe.stott;

import crypto.EngineAutoBindable;

import javax.crypto.KeyGenerator;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class StottKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();
    private int keySize = StottSecretKey.MINIMUM_KEY_SIZE;


    @Override
    public String getBind() {
        return "KeyGenerator." + StottCipher.ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("Stott key generation does not take any parameters");
    }

    @Override
    protected void engineInit(int keySize, SecureRandom secureRandom) {
        if (keySize % 8 != 0 || StottSecretKey.isKeySizeNotValid(keySize / 8))
            throw new InvalidParameterException(StottSecretKey.getKeySizeError(keySize / 8));

        this.keySize = keySize / 8;
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        try {
            int cipherKeySize = StottSecretKey.getCipherKeySize(keySize);

            KeyGenerator keyGenerator = KeyGenerator.getInstance(StottSecretKey.CIPHER_ALGORITHM);
            keyGenerator.init(cipherKeySize * 8);
            SecretKey cipherKey = keyGenerator.generateKey();

            byte[] padSeed = secureRandom.generateSeed(keySize - cipherKeySize);

            return new StottSecretKey(cipherKey.getEncoded(), padSeed);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            // never thrown
            throw new ProviderException(e);
        }
    }

}
