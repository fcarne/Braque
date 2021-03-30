package crypto.algorithm.ope.acnf;

import java.security.spec.AlgorithmParameterSpec;

public class ACNFAlgorithmParameterSpec implements AlgorithmParameterSpec {
    public static final int DEFAULT_N = 8;
    public static final byte DEFAULT_L = 0;

    private final int n;
    private final byte l;

    public ACNFAlgorithmParameterSpec(int n, byte l) {
        this.n = n > 0 ? n : DEFAULT_N;
        this.l = l > 0 ? l : DEFAULT_L;
    }

    public ACNFAlgorithmParameterSpec() {
        this(DEFAULT_N, DEFAULT_L);
    }

    public int getN() {
        return n;
    }

    public byte getL() {
        return l;
    }
}
