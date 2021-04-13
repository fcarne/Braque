package crypto.algorithm.ope.tym;

import crypto.EngineAutoBindable;
import org.apache.commons.math3.distribution.BinomialDistribution;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class TYMKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();
    private int keySize = TYMSecretKey.MINIMUM_KEY_SIZE;
    private TYMParameterSpec parameterSpec = new TYMParameterSpec();

    @Override
    public String getBind() {
        return "KeyGenerator." + TYMCipher.ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof TYMParameterSpec))
            throw new InvalidAlgorithmParameterException("algorithmParameterSpec must be of type " + TYMParameterSpec.class.getName());

        parameterSpec = (TYMParameterSpec) algorithmParameterSpec;
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int keySize, SecureRandom secureRandom) {
        if (keySize % 8 != 0 || TYMSecretKey.isKeySizeNotValid(keySize / 8))
            throw new InvalidParameterException(TYMSecretKey.getKeySizeError(keySize / 8));

        this.keySize = keySize / 8;
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        byte[] k = new byte[keySize - TYMSecretKey.FIXED_LENGTH];
        secureRandom.nextBytes(k);

        int a = -parameterSpec.getK() * parameterSpec.getTheta() - 1;
        TYMInterval intervalM = init(a);

        try {
            return new TYMSecretKey(a, parameterSpec.getM(), intervalM, k);
        } catch (InvalidKeyException ex) {
            // never thrown
            throw new ProviderException(ex);
        }
    }

    private TYMInterval init(int a) {
        int theta = parameterSpec.getTheta();
        int m = parameterSpec.getM();
        double p = 1 - Math.pow((1 - 1 / Math.sqrt(parameterSpec.getK())), 1.0 / theta);

        /*ScriptEngine engine = new RenjinScriptEngineFactory().getScriptEngine()
        engine.put("N", m - a);
        engine.put("p", p);
        engine.put("multiplier", Math.pow(2, parameterSpec.getLambda()) * Math.pow(theta, 2));

        long c0 = 0;
        long c1 = 0;

        try {
            IntVector vector = (IntVector) engine.eval("c1 <- rbinom(1, N, 1 - p); " +
                    "c0 <- rbinom(1, multiplier * (N - c1), 1/2);" +
                    "c(c0, c1) ");

            c0 = vector.getElementAsInt(0);
            c1 = vector.getElementAsInt(1);
        } catch (ScriptException e) {
            e.printStackTrace();
        }*/

        long c1 = new BinomialDistribution(m - a, 1 - p).sample();
        long c0 = new BinomialDistribution((int) (Math.pow(2,
                parameterSpec.getLambda()) * Math.pow(theta, 2) * (m - a - c1)), 1.0 / 2).sample();

        return new TYMInterval(c0, c1);
    }

}
