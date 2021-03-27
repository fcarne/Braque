package crypto.algortihm.ope.fope;

import java.security.spec.AlgorithmParameterSpec;

public class FOPEAlgorithmParameterSpec implements AlgorithmParameterSpec {

    public static final int DEFAULT_TAU = 16;
    public static final int DEFAULT_D = 8;

    private final int tau;
    private final int d;

    public FOPEAlgorithmParameterSpec() {
        this(DEFAULT_TAU, DEFAULT_D);
    }

    public FOPEAlgorithmParameterSpec(int tau, int d) {
        this.tau = tau > 0 ? tau : DEFAULT_TAU;
        this.d = d > 0 ? d : DEFAULT_D;
    }


    public int getTau() {
        return tau;
    }

    public int getD() {
        return d;
    }
}
