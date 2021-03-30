package crypto.algorithm.ope.cope;

import java.security.spec.AlgorithmParameterSpec;

public class COPEAlgorithmParameterSpec implements AlgorithmParameterSpec {
    public static final long DEFAULT_D = 256;
    public static final int DEFAULT_K = 16;

    private final long d;
    private final int k;


    public COPEAlgorithmParameterSpec(long d, int k) {
        this.d = d;
        this.k = k;
    }
    public COPEAlgorithmParameterSpec(long d) {
        this(d, DEFAULT_K);
    }
    public COPEAlgorithmParameterSpec(int k) {
        this(DEFAULT_D, k);
    }

    public COPEAlgorithmParameterSpec() {
        this(DEFAULT_D, DEFAULT_K);
    }

    public long getD() {
        return d;
    }

    public int getK() {
        return k;
    }
}
