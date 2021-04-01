package crypto.algorithm.ope.cope;

import java.security.spec.AlgorithmParameterSpec;

public class COPEAlgorithmParameterSpec implements AlgorithmParameterSpec {
    public static final long DEFAULT_D = 256;
    public static final int DEFAULT_BETAS = 8;

    private final long d;
    private final int betas;


    public COPEAlgorithmParameterSpec(long d, int betas) {
        this.d = d;
        this.betas = betas;
    }
    public COPEAlgorithmParameterSpec(long d) {
        this(d, DEFAULT_BETAS);
    }
    public COPEAlgorithmParameterSpec(int k) {
        this(DEFAULT_D, k);
    }

    public COPEAlgorithmParameterSpec() {
        this(DEFAULT_D, DEFAULT_BETAS);
    }

    public long getD() {
        return d;
    }

    public int getBetas() {
        return betas;
    }
}
