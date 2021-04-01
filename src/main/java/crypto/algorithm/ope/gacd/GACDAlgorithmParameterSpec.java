package crypto.algorithm.ope.gacd;

import java.security.spec.AlgorithmParameterSpec;

public class GACDAlgorithmParameterSpec implements AlgorithmParameterSpec {

    public static final int DEFAULT_LAMBDA = 126;
    public static final long DEFAULT_M = 256;

    private final int lambda;

    public GACDAlgorithmParameterSpec() {
        this(DEFAULT_LAMBDA + 2, DEFAULT_M);
    }

    public GACDAlgorithmParameterSpec(int keySize, long m) {
        int lambda = keySize - 2;
        if ((double) lambda < 8.0 / 3 * Math.log(m) / Math.log(2)) throw new IllegalArgumentException("Lambda is less than 8/3 * log2(m)");
        this.lambda = lambda;
    }

    public int getLambda() {
        return lambda;
    }

}
