package crypto.algorithm.ppe.stott;

import java.security.spec.AlgorithmParameterSpec;

public class StottParameterSpec implements AlgorithmParameterSpec {
    private static final int DEFAULT_MAX_LENGTH = 16;

    private int maxLength;

    public StottParameterSpec(int maxLength) {
        this.maxLength = maxLength;
    }

    public StottParameterSpec() {
        this(DEFAULT_MAX_LENGTH);
    }

    public int getMaxLength() {
        return maxLength;
    }

    public int getBitsMaxLength() {
        return maxLength * 8;
    }

    public void setMaxLength(int maxLength) {
        this.maxLength = maxLength;
    }
}
