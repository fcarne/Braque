package crypto.algorithm.ppe.cryptopan;

import java.security.spec.AlgorithmParameterSpec;

public class CryptoPanAlgorithmParameterSpec implements AlgorithmParameterSpec {
    private static final int MAX_LENGTH = 16;

    private int maxLength;

    public CryptoPanAlgorithmParameterSpec(int maxLength) {
        this.maxLength = maxLength;
    }

    public CryptoPanAlgorithmParameterSpec() {
        this(MAX_LENGTH);
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
