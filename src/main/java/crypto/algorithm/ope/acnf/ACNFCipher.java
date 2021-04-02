package crypto.algorithm.ope.acnf;

import crypto.EngineAutoBindable;
import crypto.algorithm.ope.fope.FOPEAlgorithmParameterSpec;
import crypto.algorithm.ope.fope.FOPESecretKeySpec;
import org.apache.commons.math3.analysis.integration.RombergIntegrator;
import org.apache.commons.math3.analysis.integration.UnivariateIntegrator;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class ACNFCipher extends CipherSpi implements EngineAutoBindable {

    public static final String ALGORITHM_NAME = "ArithmeticCoding";

    private int opmode;

    private int ratiosNumber = ACNFAlgorithmParameterSpec.DEFAULT_RATIOS_NUMBER;
    private int n = ACNFAlgorithmParameterSpec.DEFAULT_N;

    private byte l;
    private ACNFNoiseFunction function;
    private final UnivariateIntegrator integrator = new RombergIntegrator();

    private Ratio[] ratios;


    @Override
    public String getBind() {
        return "Cipher." + ALGORITHM_NAME;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException(ALGORITHM_NAME + " does not support different modes");
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException(ALGORITHM_NAME + " does not support different padding mechanisms");
    }

    @Override
    protected int engineGetBlockSize() {
        return 1;
    }

    @Override
    protected int engineGetOutputSize(int i) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        this.opmode = opmode;
        if (key instanceof ACNFSecretKeySpec) {
            ACNFSecretKeySpec.Raw raw = ((ACNFSecretKeySpec) key).decodeKey();

            l = raw.getL();

            SecureRandom random;
            try {
                random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
            random.setSeed(raw.getSeed());
            function = new ACNFNoiseFunction(generateA(secureRandom));

            ratios = generateRatios(random);

        } else throw new InvalidKeyException("The key used is not an ACNF Key");
    }

    private Ratio[] generateRatios(SecureRandom random) {
        Ratio[] ratios = new Ratio[ratiosNumber];
        double fMax = function.value(Math.pow(2, n));
        double product;

        do {
            product = 1;
            for (int i = 0; i < ratiosNumber; i++) {
                Ratio r = new Ratio((short) random.nextInt(Short.MAX_VALUE), (short) random.nextInt(Short.MAX_VALUE));
                ratios[i] = r;
                product *= ((double) Math.max(r.p, r.q)) / (r.p + r.q);
            }
        } while ((product * fMax) > 1 / Math.pow(2, n + l));

        return ratios;
    }

    private double[] generateA(SecureRandom random) {
        double[] a = new double[10];

        a[0] = random.doubles().findFirst().orElse(Double.NaN);
        a[2] = random.doubles().findFirst().orElse(Double.NaN);
        double a1Max = Math.sqrt(4 * a[0] * a[2]);
        a[1] = random.doubles(-a1Max, a1Max).findFirst().orElse(Double.NaN);


        a[3] = random.doubles(0, 10).findFirst().orElse(Double.NaN);
        a[4] = random.doubles().filter(v -> Math.abs(v) < a[3] / 2).findFirst().orElse(Double.NaN);
        a[7] = random.doubles().filter(v -> Math.abs(v) + Math.abs(a[4]) < a[3]).findFirst().orElse(Double.NaN);

        a[5] = random.doubles().findFirst().orElse(Double.NaN);
        a[6] = random.doubles().findFirst().orElse(Double.NaN);
        a[8] = random.doubles().findFirst().orElse(Double.NaN);
        a[9] = random.doubles().findFirst().orElse(Double.NaN);

        System.out.println("AAAA");
        Arrays.stream(a).forEach(System.out::println);

        System.out.println(integrator.integrate(100000, new ACNFNoiseFunction(a), 0, Math.pow(2, n)));

        return a;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (algorithmParameterSpec instanceof ACNFAlgorithmParameterSpec) {
            n = ((ACNFAlgorithmParameterSpec) algorithmParameterSpec).getN();
            ratiosNumber = ((ACNFAlgorithmParameterSpec) algorithmParameterSpec).getRatiosNumber();
        } else throw new InvalidAlgorithmParameterException();
        engineInit(opmode, key, secureRandom);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException {
        engineInit(opmode, key, secureRandom);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] output = null;
        if (opmode == Cipher.ENCRYPT_MODE) {
            output = new byte[ratiosNumber];
        } else if (opmode == Cipher.DECRYPT_MODE) {
            output = new byte[Long.BYTES];
        }
        engineUpdate(input, inputOffset, inputLen, output, 0);
        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (opmode == Cipher.ENCRYPT_MODE) {
            long s = ByteBuffer.wrap(input).getLong();

            BigInteger c = BigInteger.ZERO;

            double a = 0;
            double b = Math.pow(2, n);

            for (int i = 0; i < ratiosNumber; i++) {
                double x = a + (b - a) * ratios[i].p / (ratios[i].p + ratios[i].q);
                if (integrator.integrate(100000, function, 0, x) > s) {
                    b = x;
                } else {
                    a = x;
                    c = c.or(BigInteger.ONE.shiftLeft(ratiosNumber - i + 1));
                }
            }

            byte[] cipherArray = c.toByteArray();
            System.arraycopy(cipherArray, 0, output, output.length - cipherArray.length, cipherArray.length);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            BigInteger c = new BigInteger(input);

            double a = 0;
            double b = Math.pow(2, n);

            for (int i = 0; i < ratiosNumber; i++) {
                double x = a + (b - a) * ratios[i].p / (ratios[i].p + ratios[i].q);
                if (c.shiftRight(ratiosNumber - i + 1).and(BigInteger.ONE).equals(BigInteger.ZERO)) {
                    b = x;
                } else {
                    a = x;
                }
            }

            long s = BigDecimal.valueOf(2).pow(n).multiply(BigDecimal.valueOf(integrator.integrate(100000, function, 0, a)))
                    .setScale(0, RoundingMode.FLOOR).add(BigDecimal.ONE).longValue();

            System.arraycopy(ByteBuffer.allocate(Long.BYTES).putLong(s).array(), 0, output, 0, output.length);
        }

        return inputLen;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        return engineUpdate(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        return engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

    private static class Ratio {
        short p;
        short q;

        public Ratio(short p, short q) {
            this.p = p;
            this.q = q;
        }
    }

}
