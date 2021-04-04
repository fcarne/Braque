package crypto.algorithm.ope.tym;

import crypto.EngineAutoBindable;
import org.renjin.script.RenjinScriptEngineFactory;
import org.renjin.sexp.DoubleArrayVector;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class TYMCipher extends CipherSpi implements EngineAutoBindable {

    public static final String ALGORITHM_NAME = "TYM";

    private int opmode;
    private TYMAlgorithmParameterSpec parameterSpec = new TYMAlgorithmParameterSpec();

    private byte[] k;
    private int a;
    private int m;
    private TYMInterval iM;

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
        if (key instanceof TYMSecretKeySpec) {
            TYMSecretKeySpec.Raw raw = ((TYMSecretKeySpec) key).decodeKey();

            k = raw.getK();
            a = raw.getA();
            m = raw.getM();
            iM = raw.getIntervalM();

            Double multiplier = (Math.pow(2, parameterSpec.getLambda()) * Math.pow(parameterSpec.getTheta(), 2));
            engine.put("multiplier", multiplier);
        } else throw new InvalidKeyException("The key used is not a TYM Key");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (algorithmParameterSpec instanceof TYMAlgorithmParameterSpec) {
            parameterSpec = (TYMAlgorithmParameterSpec) algorithmParameterSpec;
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
            output = new byte[Long.BYTES];
        } else if (opmode == Cipher.DECRYPT_MODE) {
            output = new byte[Long.BYTES];
        }
        engineUpdate(input, inputOffset, inputLen, output, 0);
        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (opmode == Cipher.ENCRYPT_MODE) {
            long plain = ByteBuffer.wrap(input).getLong();
            long cipher = enc(plain, a, m, new TYMInterval(0, 0), iM);

            System.arraycopy(ByteBuffer.allocate(Long.BYTES).putLong(cipher).array(), 0, output, 0, output.length);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            long cipher = ByteBuffer.wrap(input).getLong();
            long plain = dec(cipher, a, m, new TYMInterval(0, 0), iM);

            System.arraycopy(ByteBuffer.allocate(Long.BYTES).putLong(plain).array(), 0, output, 0, output.length);
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

    private long enc(long plain, int u, int v, TYMInterval iU, TYMInterval iV) {

        if (plain == v) return cph(iV);

        int w = (int) Math.ceil((u + v) / 2.0);
        byte[] cc = prf(u, v);
        TYMInterval iW = g(u, v, w, iU, iV, cc);

        return plain <= w ? enc(plain, u, w, iU, iW) : enc(plain, w, v, iW, iV);
    }

    private long dec(long cipher, int u, int v, TYMInterval iU, TYMInterval iV) {

        if (cipher == cph(iV)) return v;
        if (u == v) return Long.MIN_VALUE;

        int w = (int) Math.ceil((u + v) / 2.0);
        byte[] cc = prf(u, v);
        TYMInterval iW = g(u, v, w, iU, iV, cc);

        return (cipher <= cph(iW)) ? dec(cipher, u, w, iU, iW) : dec(cipher, w, v, iW, iV);
    }

    private byte[] prf(int u, int v) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        md.update(k);
        md.update(ByteBuffer.allocate(2 * Long.BYTES).putLong(u).putLong(v).array());

        return md.digest();
    }

    private long cph(TYMInterval i) {
        return i.c0 + i.c1;
    }

    private TYMInterval g(int u, int v, int w, TYMInterval iU, TYMInterval iV, byte[] cc) {
        engine.put("seed", new BigInteger(cc).toString());
        engine.put("N1", v - u);
        engine.put("w1", iV.c1 - iU.c1);
        engine.put("d1", w - u);
        engine.put("w2", iV.c0 - iU.c0);
        engine.put("cU_0", iU.c0);
        engine.put("cU_1", iU.c1);

        long cW0 = 0;
        long cW1 = 0;
        try {
            StringWriter outputWriter = new StringWriter();
            engine.getContext().setErrorWriter(outputWriter);

            DoubleArrayVector vector = (DoubleArrayVector) engine.eval("set.seed(as.integer(seed)); " +
                    "cW_1 <- cU_1 + rhyper(1, w1, N1 - w1, d1); " +
                    "cW_0 <- cU_0 + rhyper(1, w2, multiplier * (N1 - w1) - w2, multiplier * (d1 - (cW_1 - cU_1)));" +
                    "c(cW_0, cW_1) ");

            cW0 = (long) vector.get(0);
            cW1 = (long) vector.get(1);
        } catch (ScriptException e) {
            e.printStackTrace();
        }

        return new TYMInterval(cW0, cW1);
    }
}
