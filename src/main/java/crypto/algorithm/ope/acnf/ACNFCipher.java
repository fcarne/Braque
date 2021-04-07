package crypto.algorithm.ope.acnf;

import crypto.EngineAutoBindable;
import org.renjin.script.RenjinScriptEngineFactory;
import org.renjin.sexp.SEXP;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class ACNFCipher extends CipherSpi implements EngineAutoBindable {

    public static final String ALGORITHM_NAME = "ArithmeticCoding";

    private int opmode;

    private ACNFAlgorithmParameterSpec parameterSpec = new ACNFAlgorithmParameterSpec();

    private byte l;
    private byte n;
    private Ratio[] ratios;

    private final ScriptEngine engine = new RenjinScriptEngineFactory().getScriptEngine();


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
            n = raw.getN();

            SecureRandom random;
            try {
                random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
            random.setSeed(raw.getSeed());

            double[] a = generateA(random);
            engine.put("a", a);
            engine.put("n", (int) n);

            try {
                // { (a[0] + a[1]*t + a[2] * t^2) * (a[3] + a[4] * sin(a[5] + a[6]*t) + a[7] * cos(a[8] + a[9]*t)) }
                engine.eval("fun <- function(t) {t}");
            } catch (ScriptException e) {
                e.printStackTrace();
            }

            ratios = generateRatios(random);


        } else throw new InvalidKeyException("The key used is not a " + ALGORITHM_NAME + " Key");
    }

    private Ratio[] generateRatios(SecureRandom random) {
        Ratio[] ratios = new Ratio[parameterSpec.getRatiosNumber()];
        double fMax = 1;
        try {
            fMax = ((SEXP) engine.eval("fun(2**n)")).asReal();
        } catch (ScriptException e) {
            e.printStackTrace();
        }
        double product;

        System.out.println("PPPP");
        do {
            product = 1;
            for (int i = 0; i < parameterSpec.getRatiosNumber(); i++) {
                Ratio r = new Ratio((short) random.nextInt(Short.MAX_VALUE), (short) random.nextInt(Short.MAX_VALUE));
                ratios[i] = r;
                product *= ((double) Math.max(r.p, r.q)) / (r.p + r.q);
            }
            System.out.println("P34343P");

        } while ((product * fMax) > 1 / Math.pow(2, parameterSpec.getN() + parameterSpec.getL()));


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

        return a;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (algorithmParameterSpec instanceof ACNFAlgorithmParameterSpec) {
            parameterSpec = ((ACNFAlgorithmParameterSpec) algorithmParameterSpec);
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
            output = new byte[parameterSpec.getRatiosNumber()];
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
            System.out.println(s);

            BigInteger c = BigInteger.ZERO;

            double a = 0;
            double b = Math.pow(2, parameterSpec.getN());

            for (int i = 0; i < parameterSpec.getRatiosNumber(); i++) {
                double x = a + ((b - a) * ratios[i].p) / (ratios[i].p + ratios[i].q);

                System.out.println(ratios[i].p + " -- " + ratios[i].q);
                System.out.println(x);

                engine.put("x", x);
                double fX = 0;
                try {
                    engine.eval("print(integrate(fun, 0, x))");
                    fX = ((SEXP) engine.eval("integrate(fun, 0, x)")).asReal();
                    System.out.println(fX);
                } catch (ScriptException e) {
                    e.printStackTrace();
                }

                if (fX > s) {
                    b = x;
                } else {
                    a = x;
                    c = c.or(BigInteger.ONE.shiftLeft(parameterSpec.getRatiosNumber() - i - 1));
                    System.out.println(c.toString(2));
                }
            }

            System.out.println(c);

            byte[] cipherArray = c.toByteArray();
            System.arraycopy(cipherArray, 0, output, output.length - cipherArray.length, cipherArray.length);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            BigInteger c = new BigInteger(input);

            double a = 0;
            double b = Math.pow(2, n);

            for (int i = 0; i < parameterSpec.getRatiosNumber(); i++) {
                double x = a + (b - a) * ratios[i].p / (ratios[i].p + ratios[i].q);
                if (c.shiftRight(parameterSpec.getRatiosNumber() - i + 1).and(BigInteger.ONE).equals(BigInteger.ZERO)) {
                    b = x;
                } else {
                    a = x;
                }
            }

            engine.put("x", a);
            double fX = 0;
            try {
                fX = ((SEXP) engine.eval("integrate(fun, 0, x)")).asReal();
            } catch (ScriptException e) {
                e.printStackTrace();
            }

            System.out.println(fX);
            long s = BigDecimal.valueOf(2).pow((int) n).multiply(BigDecimal.valueOf(fX))
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
