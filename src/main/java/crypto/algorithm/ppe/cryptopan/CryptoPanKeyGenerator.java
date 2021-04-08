package crypto.algorithm.ppe.cryptopan;

import crypto.EngineAutoBindable;

import javax.crypto.KeyGenerator;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigDecimal;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class CryptoPanKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();
    private CryptoPanAlgorithmParameterSpec parameterSpec = new CryptoPanAlgorithmParameterSpec();

    @Override
    public String getBind() {
        return "KeyGenerator." + CryptoPanCipher.ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof CryptoPanAlgorithmParameterSpec))
            throw new InvalidAlgorithmParameterException();
        parameterSpec = (CryptoPanAlgorithmParameterSpec) algorithmParameterSpec;
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int keySize, SecureRandom secureRandom) {
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        SecretKeySpec key = null;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            key = (SecretKeySpec) keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        byte[] pad = new byte[16];
        secureRandom.nextBytes(pad);

        return new CryptoPanSecretKeySpec.Raw().setKey(key.getEncoded()).setPad(pad).build();
    }

}
