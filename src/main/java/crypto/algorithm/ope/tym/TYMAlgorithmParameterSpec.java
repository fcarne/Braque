package crypto.algorithm.ope.tym;

import java.security.spec.AlgorithmParameterSpec;

public class TYMAlgorithmParameterSpec implements AlgorithmParameterSpec {

    public static final int DEFAULT_K = 1;
    public static final byte DEFAULT_THETA = 32;
    public static final int DEFAULT_M = 256;

    private final int k ;
    private final byte theta;
    private final int m;


    public TYMAlgorithmParameterSpec(int k, byte theta, int m) {
        this.k = k;
        this.theta = theta;
        this.m = m;
    }

    public TYMAlgorithmParameterSpec() {
        this(DEFAULT_K, DEFAULT_THETA, DEFAULT_M);
    }

    public int getK() {
        return k;
    }

    public byte getTheta() {
        return theta;
    }

    public int getM() {
        return m;
    }
}
