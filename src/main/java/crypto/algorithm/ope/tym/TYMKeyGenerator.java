package crypto.algorithm.ope.tym;

import crypto.EngineAutoBindable;
import org.apache.commons.math3.distribution.BinomialDistribution;
import org.renjin.script.RenjinScriptEngineFactory;
import org.renjin.sexp.IntVector;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

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
    protected void engineInit(int keySize, SecureRandom secureRandom) {
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
