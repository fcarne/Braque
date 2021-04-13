package crypto.algorithm.ope.aicd;

import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;

public class AICDParameterSpec implements AlgorithmParameterSpec {

    private static final int DEFAULT_LAMBDA = 126;
    private static final long DEFAULT_M = 256;

    private int lambda;

    public AICDParameterSpec() {
        this(DEFAULT_LAMBDA + 2, DEFAULT_M);
    }

    public AICDParameterSpec(int keySize, long m) {
        setLambda(keySize, m);
    }

    public int getLambda() {
        return lambda;
    }

    public void setLambda(int keySize, long m) {
        if (keySize % 8 != 0 || AICDSecretKey.isKeySizeNotValid(keySize / 8))
            throw new InvalidParameterException(AICDSecretKey.getKeySizeError(keySize / 8));

        int lambda = keySize - 2;
        if (!checkSuperPolynomial(lambda, m)) throw new IllegalArgumentException("Lambda is less than 8/3 * log2(m)");
        this.lambda = lambda;
    }

    private boolean checkSuperPolynomial(int lambda, long m) {
        return lambda > 8.0 / 3 * Math.log(m) / Math.log(2);
    }

}
