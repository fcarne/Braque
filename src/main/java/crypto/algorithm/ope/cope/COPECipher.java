package crypto.algorithm.ope.cope;

import crypto.EngineAutoBindable;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class COPECipher extends CipherSpi implements EngineAutoBindable {

    public static final String ALGORITHM_NAME = "ChaoticOPE";
    private static final BigDecimal EPSILON = BigDecimal.valueOf(0.0000001D);

    private int opmode;

    private double p;
    private int betas = COPEAlgorithmParameterSpec.DEFAULT_BETAS;

    private BigDecimal[] beta;
    private BigDecimal[] b;

    @Override
    public String getBind() {
        return "Cipher." + ALGORITHM_NAME;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("COPE does not support different modes");
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("COPE does not support different padding mechanisms");
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
        if (key instanceof COPESecretKeySpec) {
            COPESecretKeySpec.Raw raw = ((COPESecretKeySpec) key).decodeKey();
            this.p = raw.getP();

            SecureRandom random;
            try {
                random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
            random.setSeed(raw.getSeed());

            List<Double> intervals = new ArrayList<>();
            double maxLength = p;
            for (int i = 0; i < betas - 1; i++) {
                double interval = random.doubles(0, maxLength / 2).findFirst().orElse(0);
                maxLength -= interval;
                intervals.add(interval);
            }
            intervals.add(maxLength);
            intervals.sort(Collections.reverseOrder());

            b = new BigDecimal[betas + 1];
            b[0] = BigDecimal.ZERO;
            for (int i = 1; i < betas + 1; i++) {
                b[i] = b[i - 1].add(BigDecimal.valueOf(intervals.get(i - 1)));
            }

            beta = new BigDecimal[betas];
            for (int i = 0; i < betas; i++) {
                beta[i] = BigDecimal.valueOf(p).divide(BigDecimal.valueOf(intervals.get(i)), RoundingMode.HALF_UP);
            }

            //TODO calcolare max length
        } else throw new InvalidKeyException("The key used is not a COPE Key");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof COPEAlgorithmParameterSpec))
            throw new InvalidAlgorithmParameterException();
        betas = ((COPEAlgorithmParameterSpec) algorithmParameterSpec).getBetas();
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
            output = new byte[Double.BYTES * 2];
        } else if (opmode == Cipher.DECRYPT_MODE) {
            output = new byte[Double.BYTES];
        }
        engineUpdate(input, inputOffset, inputLen, output, 0);
        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (opmode == Cipher.ENCRYPT_MODE) {

            BigDecimal r = BigDecimal.valueOf(ByteBuffer.wrap(input).getDouble());
            List<BigInteger> w = new ArrayList<>();

            do {
                BigDecimal theta = BigDecimal.ZERO;
                for (int i = 1; i < b.length; i++) {
                    if (r.compareTo(b[i]) < 0) {
                        theta = beta[i - 1];
                        break;
                    }
                }
                BigDecimal[] wAndR = theta.multiply(r).divideAndRemainder(BigDecimal.valueOf(p));
                w.add(wAndR[0].toBigInteger());
                r = wAndR[1];
            } while (isRepeat(stringify(w)));

            w.forEach(System.out::println);

        } else if (opmode == Cipher.DECRYPT_MODE) {
        }

        return inputLen;
    }

    private String stringify(List<BigInteger> w) {
        StringBuilder s = new StringBuilder();
        for (BigInteger b : w) {
            s.append(b.toString());
        }
        return s.toString();
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        return engineUpdate(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        return engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

    static void computeLPSArray(String str, int M, int[] lps) {
        // lenght of the previous
        // longest prefix suffix
        int len = 0;

        int i;

        lps[0] = 0; // lps[0] is always 0
        i = 1;

        // the loop calculates lps[i]
        // for i = 1 to M-1
        while (i < M) {
            if (str.charAt(i) == str.charAt(len)) {
                len++;
                lps[i] = len;
                i++;
            } else // (pat[i] != pat[len])
            {
                if (len != 0) {
                    // This is tricky. Consider the
                    // example AAACAAAA and i = 7.
                    len = lps[len - 1];

                    // Also, note that we do
                    // not increment i here
                } else // if (len == 0)
                {
                    lps[i] = 0;
                    i++;
                }
            }
        }
    }

    // Returns true if str is repetition of
// one of its substrings else return false.
    static boolean isRepeat(String str) {
        // Find length of string and create
        // an array to store lps values used in KMP
        int n = str.length();
        int[] lps = new int[n];

        // Preprocess the pattern (calculate lps[] array)
        computeLPSArray(str, n, lps);

        // Find length of longest suffix
        // which is also prefix of str.
        int len = lps[n - 1];

        // If there exist a suffix which is also
        // prefix AND Length of the remaining substring
        // divides total length, then str[0..n-len-1]
        // is the substring that repeats n/(n-len)
        // times (Readers can print substring and
        // value of n/(n-len) for more clarity.
        return len > 0 && n % (n - len) == 0;
    }

}
