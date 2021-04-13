package crypto.algorithm.ope.tym;

import java.security.spec.AlgorithmParameterSpec;

public class TYMParameterSpec implements AlgorithmParameterSpec {
    //TODO rivedere set per controllare valori
    private static final int DEFAULT_K = 256;
    private static final int DEFAULT_THETA = 16;
    private static final int DEFAULT_M = 256;
    private static final int DEFAULT_LAMBDA = 8;

    private int k;
    private int theta;
    private int m;
    private int lambda;

    public TYMParameterSpec(int k, int theta, int m, int lambda) {
        this.k = k;
        this.theta = theta;
        this.m = m;
        this.lambda = lambda;
    }

    public TYMParameterSpec() {
        this(DEFAULT_K, DEFAULT_THETA, DEFAULT_M, DEFAULT_LAMBDA);
    }

    public int getK() {
        return k;
    }

    public void setK(int k) {
        this.k = k;
    }

    public int getTheta() {
        return theta;
    }

    public void setTheta(int theta) {
        this.theta = theta;
    }

    public int getM() {
        return m;
    }

    public void setM(int m) {
        this.m = m;
    }

    public int getLambda() {
        return lambda;
    }

    public void setLambda(int lambda) {
        this.lambda = lambda;
    }
}
