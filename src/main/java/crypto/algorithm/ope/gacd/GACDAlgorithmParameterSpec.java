package crypto.algorithm.ope.gacd;

import java.security.spec.AlgorithmParameterSpec;

public class GACDAlgorithmParameterSpec implements AlgorithmParameterSpec {

    private static final int DEFAULT_LAMBDA = 126;
    private static final long DEFAULT_M = 256;

    private int lambda;

    public GACDAlgorithmParameterSpec() {
        this(DEFAULT_LAMBDA + 2, DEFAULT_M);
    }

    public GACDAlgorithmParameterSpec(int keySize, long m) {
        setLambda(keySize, m);
    }

    private boolean checkSuperPolynomial(int lambda, long m) {
        return lambda > 8.0 / 3 * Math.log(m) / Math.log(2);
    }

    public int getLambda() {
        return lambda;
    }

    public void setLambda(int keySize, long m) {
        int lambda = keySize - 2;
        if (!checkSuperPolynomial(lambda, m)) throw new IllegalArgumentException("Lambda is less than 8/3 * log2(m)");
        this.lambda = lambda;
    }

}
