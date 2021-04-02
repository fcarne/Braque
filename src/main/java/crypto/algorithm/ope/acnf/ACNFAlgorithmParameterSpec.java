package crypto.algorithm.ope.acnf;

import java.security.spec.AlgorithmParameterSpec;

public class ACNFAlgorithmParameterSpec implements AlgorithmParameterSpec {
    public static final int DEFAULT_N = 16;
    public static final byte DEFAULT_L = 0;
    public static final int DEFAULT_RATIOS_NUMBER = 64;

    private final int n;
    private final byte l;
    private final int ratiosNumber;

    public ACNFAlgorithmParameterSpec(int n, byte l, int ratiosNumber) {
        this.n = n > 0 ? n : DEFAULT_N;
        this.l = l > 0 ? l : DEFAULT_L;
        this.ratiosNumber = ratiosNumber > 0 ? ratiosNumber : DEFAULT_RATIOS_NUMBER;
    }

    public ACNFAlgorithmParameterSpec() {
        this(DEFAULT_N, DEFAULT_L, DEFAULT_RATIOS_NUMBER);
    }

    public int getN() {
        return n;
    }

    public byte getL() {
        return l;
    }

    public int getRatiosNumber() {
        return ratiosNumber;
    }
}
