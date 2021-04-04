package crypto.algorithm.ope.tym;

import crypto.EngineAutoBindable;
import org.apache.commons.math3.distribution.BinomialDistribution;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class TYMKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();
    private TYMAlgorithmParameterSpec parameterSpec = new TYMAlgorithmParameterSpec();

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
        if (!(algorithmParameterSpec instanceof TYMAlgorithmParameterSpec))
            throw new InvalidAlgorithmParameterException();
        parameterSpec = (TYMAlgorithmParameterSpec) algorithmParameterSpec;
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int i, SecureRandom secureRandom) {
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        byte[] k = new byte[16];
        secureRandom.nextBytes(k);
        int a = -parameterSpec.getK() * parameterSpec.getTheta() - 1;
        TYMInterval intervalM = init(a);

        return new TYMSecretKeySpec.Raw().setK(k).setA(a).setM(parameterSpec.getM()).setIntervalM(intervalM).build();
    }

    private TYMInterval init(int a) {
        int theta = parameterSpec.getTheta();
        int m = parameterSpec.getM();
        double p = 1 - Math.pow((1 - 1 / Math.sqrt(parameterSpec.getK())), 1.0 / theta);

        long c1 = new BinomialDistribution(m - a, 1 - p).sample();
        long c0 = new BinomialDistribution((int) (Math.pow(2,
                parameterSpec.getLambda()) * Math.pow(theta, 2) * (m - a - c1)), 1.0 / 2).sample();

        return new TYMInterval(c0, c1);
    }

}
