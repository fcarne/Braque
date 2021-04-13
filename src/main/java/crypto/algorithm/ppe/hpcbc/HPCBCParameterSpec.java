package crypto.algorithm.ppe.hpcbc;

import java.security.spec.AlgorithmParameterSpec;

public class HPCBCParameterSpec implements AlgorithmParameterSpec {
    private static final int DEFAULT_BLOCKSIZE = 8;

    private int blockSize;

    public HPCBCParameterSpec(int blockSize) {
        this.blockSize = blockSize;
    }

    public HPCBCParameterSpec() {
        this(DEFAULT_BLOCKSIZE);
    }

    public int getBlockSize() {
        return blockSize;
    }

    public void setBlockSize(int blockSize) {
        this.blockSize = blockSize;
    }
}
