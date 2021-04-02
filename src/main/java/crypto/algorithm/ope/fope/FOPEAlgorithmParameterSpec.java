package crypto.algorithm.ope.fope;

import java.security.spec.AlgorithmParameterSpec;

public class FOPEAlgorithmParameterSpec implements AlgorithmParameterSpec {

    public static final int DEFAULT_TAU = 16;
    public static final byte DEFAULT_D = 8;

    private final int tau;
    private final byte d;

    public FOPEAlgorithmParameterSpec() {
        this(DEFAULT_TAU, DEFAULT_D);
    }

    public FOPEAlgorithmParameterSpec(int tau) {
        this(tau, DEFAULT_D);
    }

    public FOPEAlgorithmParameterSpec(byte d) {
        this(DEFAULT_TAU, d);
    }

    public FOPEAlgorithmParameterSpec(int tau, byte d) {
        this.tau = tau > 0 ? tau : DEFAULT_TAU;
        this.d = d > 0 ? d : DEFAULT_D;
    }

    public int getTau() {
        return tau;
    }

    public byte getD() {
        return d;
    }
}
