package crypto.algorithm.ope.piore;

import java.security.spec.AlgorithmParameterSpec;

public class PIOREParameterSpec implements AlgorithmParameterSpec {
    private static final byte DEFAULT_N = 8;

    private byte n;

    public PIOREParameterSpec(byte n) {
        this.n = n > 0 ? n : DEFAULT_N;
    }

    public PIOREParameterSpec() {
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
