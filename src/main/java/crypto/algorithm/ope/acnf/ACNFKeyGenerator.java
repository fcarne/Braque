package crypto.algorithm.ope.acnf;

import crypto.EngineAutoBindable;
import crypto.algorithm.ope.fope.FOPECipher;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class ACNFKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();
    private int size = ACNFSecretKeySpec.DEFAULT_SIZE;
    private int n = ACNFAlgorithmParameterSpec.DEFAULT_N;
    private byte l = ACNFAlgorithmParameterSpec.DEFAULT_L;

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
        if (!(algorithmParameterSpec instanceof ACNFAlgorithmParameterSpec))
            throw new InvalidAlgorithmParameterException();
        this.n = ((ACNFAlgorithmParameterSpec) algorithmParameterSpec).getN();
        this.l = ((ACNFAlgorithmParameterSpec) algorithmParameterSpec).getL();
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int size, SecureRandom secureRandom) {
        if (size % ACNFSecretKeySpec.DEFAULT_SIZE == 0)
            this.size = size;
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        byte c = (byte) secureRandom.nextInt(Byte.MAX_VALUE);
        try {
            return new ACNFSecretKeySpec.Raw(size).setL(l).build();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

}
