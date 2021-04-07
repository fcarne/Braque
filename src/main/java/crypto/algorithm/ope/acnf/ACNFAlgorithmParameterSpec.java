package crypto.algorithm.ope.acnf;

import java.security.spec.AlgorithmParameterSpec;

public class ACNFAlgorithmParameterSpec implements AlgorithmParameterSpec {
    private static final byte DEFAULT_N = 16;
    private static final byte DEFAULT_L = 0;
    private static final int DEFAULT_RATIOS_NUMBER = 64;

    private byte n;
    private byte l;
    private int ratiosNumber;

    public ACNFAlgorithmParameterSpec(byte n, byte l, int ratiosNumber) {
        this.n = n > 0 ? n : DEFAULT_N;
        this.l = l > 0 ? l : DEFAULT_L;
        this.ratiosNumber = ratiosNumber > 0 ? ratiosNumber : DEFAULT_RATIOS_NUMBER;
    }

    public ACNFAlgorithmParameterSpec() {
        this(DEFAULT_N, DEFAULT_L, DEFAULT_RATIOS_NUMBER);
    }

    public byte getN() {
        return n;
    }

    public void setN(byte n) {
        this.n = n;
    }

    public byte getL() {
        return l;
    }

    public void setL(byte l) {
        this.l = l;
    }

    public int getRatiosNumber() {
        return ratiosNumber;
    }

    public void setRatiosNumber(int ratiosNumber) {
        this.ratiosNumber = ratiosNumber;
    }
}
