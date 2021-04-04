package crypto.algorithm.ope.fope;

import java.security.spec.AlgorithmParameterSpec;

public class FOPEAlgorithmParameterSpec implements AlgorithmParameterSpec {

    private static final int DEFAULT_TAU = 16;
    private static final byte DEFAULT_D = 8;

    private int tau;
    private byte d;

    public FOPEAlgorithmParameterSpec() {
        this(DEFAULT_TAU, DEFAULT_D);
    }

    public FOPEAlgorithmParameterSpec(int tau, byte d) {
        this.tau = tau > 0 ? tau : DEFAULT_TAU;
        this.d = d > 0 ? d : DEFAULT_D;
    }

    public int getTau() {
        return tau;
    }

    public void setTau(int tau) {
        if (tau > 0)
            this.tau = tau;
    }

    public byte getD() {
        return d;
    }

    public void setD(byte d) {
        if (d > 0)
            this.d = d;
    }
}
