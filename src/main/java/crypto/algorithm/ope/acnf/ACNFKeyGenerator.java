package crypto.algorithm.ope.acnf;

import crypto.EngineAutoBindable;
import crypto.algorithm.ope.fope.FOPECipher;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class ACNFKeyGenerator extends KeyGeneratorSpi implements EngineAutoBindable {

    private SecureRandom secureRandom = new SecureRandom();
    private int size = ACNFSecretKeySpec.DEFAULT_SIZE;
    private int n = ACNFAlgorithmParameterSpec.DEFAULT_N;
    private byte l = ACNFAlgorithmParameterSpec.DEFAULT_L;

    @Override
    public String getBind() {
        return "KeyGenerator." + ACNFCipher.ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof ACNFAlgorithmParameterSpec))
            throw new InvalidAlgorithmParameterException();
        this.n = ((ACNFAlgorithmParameterSpec) algorithmParameterSpec).getN();
        this.l = ((ACNFAlgorithmParameterSpec) algorithmParameterSpec).getL();
        engineInit(secureRandom);
    }

    @Override
    protected void engineInit(int size, SecureRandom secureRandom) {
        if (size % ACNFSecretKeySpec.DEFAULT_SIZE == 0)
            this.size = size;
        engineInit(secureRandom);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        byte c = (byte) (secureRandom.nextInt(2 * Byte.MAX_VALUE) + Byte.MIN_VALUE);
        byte[] a = generateA();

        int ratiosLength = ACNFSecretKeySpec.getRatiosLength(size);

        short[] p = new short[ratiosLength];
        short[] q = new short[ratiosLength];

        double fMax = new ACNFNoiseFunction(a).value(Math.pow(2, n));
        double product;
        do {
            product = 1;
            for (int i = 0; i < ratiosLength; i++) {
                p[i] = (short) secureRandom.nextInt(Short.MAX_VALUE);
                q[i] = (short) secureRandom.nextInt(Short.MAX_VALUE);
                product *= ((double) Math.max(p[i], q[i])) / (p[i] + q[i]);
            }
            System.out.println((product * fMax));
        } while ((product * fMax) > 1 / Math.pow(2, n));

        try {
            return new ACNFSecretKeySpec.Raw(size).setL(l).setC(c).setA(a).setP(p).setQ(q).build();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] generateA() {
        byte[] a = new byte[10];
        secureRandom.nextBytes(a);

        a[0] &= Byte.MAX_VALUE;
        a[2] &= Byte.MAX_VALUE;
        int a2Max = (int) Math.floor(Math.sqrt(4 * a[0] * a[2]));
        if (a2Max > Byte.MAX_VALUE) a2Max = Byte.MAX_VALUE;
        a[1] = (byte) (secureRandom.nextInt(2 * a2Max) - a2Max);

        a[3] &= Byte.MAX_VALUE;
        while (a[3] < a[4] + a[7]) {
            a[4] = (byte) (secureRandom.nextInt(a[3] + (-Byte.MIN_VALUE)) + Byte.MIN_VALUE);
            a[7] = (byte) (secureRandom.nextInt(a[3] - a[4] + (-Byte.MIN_VALUE)) + Byte.MIN_VALUE);
            System.out.println(Arrays.toString(a));
        }

        return a;
    }

}
