package crypto.algorithm.ope.piore;

import java.security.spec.AlgorithmParameterSpec;

public class PIOREAlgorithmParameterSpec implements AlgorithmParameterSpec {
    private static final byte DEFAULT_N = 8;

    private byte n;

    public PIOREAlgorithmParameterSpec(byte n) {
        this.n = n;
    }

    public PIOREAlgorithmParameterSpec() {
        this(DEFAULT_N);
    }

    public byte getN() {
        return n;
    }

    public void setN(byte n) {
        if (n > 0)
            this.n = n;
    }
}
