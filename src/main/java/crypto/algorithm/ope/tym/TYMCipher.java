package crypto.algorithm.ope.tym;

import crypto.algorithm.GaloisCipher;
import crypto.algorithm.ope.fope.FOPEParameterSpec;
import org.renjin.script.RenjinScriptEngine;
import org.renjin.script.RenjinScriptEngineFactory;
import org.renjin.sexp.DoubleArrayVector;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.script.ScriptException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class TYMCipher extends GaloisCipher {

    public static final String ALGORITHM_NAME = "TYM";
    private static final String PRF_ALGORITHM = "HmacSha256";

    private TYMParameterSpec parameterSpec = new TYMParameterSpec();

    private int a;
    private int m;
    private TYMInterval iM;

    private final Mac mac;

    private final RenjinScriptEngine engine = new RenjinScriptEngineFactory().getScriptEngine();

    public TYMCipher() throws NoSuchAlgorithmException {
        mac = Mac.getInstance(PRF_ALGORITHM);
    }

    @Override
    public String getBind() {
        return "Cipher." + ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(int opMode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        this.opMode = opMode;
        byte[] keyBytes = getKeyBytes(key);
        TYMSecretKey tymKey = new TYMSecretKey(keyBytes);

        a = tymKey.getA();
        m = tymKey.getM();
        iM = tymKey.getIntervalM();

        mac.init(new SecretKeySpec(tymKey.getK(), PRF_ALGORITHM));

        Double multiplier = (Math.pow(2, parameterSpec.getLambda()) * Math.pow(parameterSpec.getTheta(), 2));
        engine.put("multiplier", multiplier);
    }

    @Override
    protected void engineInit(int opMode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (algorithmParameterSpec instanceof TYMParameterSpec) {
            parameterSpec = (TYMParameterSpec) algorithmParameterSpec;
        } else
            throw new InvalidAlgorithmParameterException("algorithmParameterSpec must be of type " + TYMParameterSpec.class.getName());
        engineInit(opMode, key, secureRandom);
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return Long.BYTES;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        if (opMode == Cipher.ENCRYPT_MODE) {
            long plain = ByteBuffer.wrap(input).getLong();
            long cipher = enc(plain, a, m, new TYMInterval(0, 0), iM);

            System.arraycopy(ByteBuffer.allocate(Long.BYTES).putLong(cipher).array(), 0, output, 0, output.length);
        } else if (opMode == Cipher.DECRYPT_MODE) {
            long cipher = ByteBuffer.wrap(input).getLong();
            long plain = dec(cipher, a, m, new TYMInterval(0, 0), iM);

            System.arraycopy(ByteBuffer.allocate(Long.BYTES).putLong(plain).array(), 0, output, 0, output.length);
        }
        return inputLen;
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


    private long cph(TYMInterval i) {
        return i.c0 + i.c1;
    }

    private TYMInterval g(int u, int v, int w, TYMInterval iU, TYMInterval iV, byte[] cc) {
        long cW0 = 0;
        long cW1 = 0;
        try {
            DoubleArrayVector vector;

            synchronized (engine) {
                engine.put("seed", new BigInteger(cc).toString());
                engine.put("N1", v - u);
                engine.put("w1", iV.c1 - iU.c1);
                engine.put("d1", w - u);
                engine.put("w2", iV.c0 - iU.c0);
                engine.put("cU_0", iU.c0);
                engine.put("cU_1", iU.c1);

                vector = (DoubleArrayVector) engine.eval("set.seed(as.integer(seed)); " +
                        "cW_1 <- cU_1 + rhyper(1, w1, N1 - w1, d1); " +
                        "cW_0 <- cU_0 + rhyper(1, w2, multiplier * (N1 - w1) - w2, multiplier * (d1 - (cW_1 - cU_1)));" +
                        "c(cW_0, cW_1) ");
            }
            cW0 = (long) vector.get(0);
            cW1 = (long) vector.get(1);
        } catch (ScriptException e) {
            e.printStackTrace();
        }

        return new TYMInterval(cW0, cW1);
    }

    private byte[] prf(int u, int v) {
        byte[] message = ByteBuffer.allocate(2 * Integer.BYTES).putInt(u).putInt(v).array();
        try {
            Mac macClone = (Mac) mac.clone();
            return macClone.doFinal(message);
        } catch (CloneNotSupportedException e) {
            // never thrown
            throw new ProviderException(e);
        }

    }
}
