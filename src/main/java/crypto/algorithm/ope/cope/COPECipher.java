package crypto.algorithm.ope.cope;

import crypto.EngineAutoBindable;
import crypto.algorithm.ope.fope.FOPEAlgorithmParameterSpec;

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
import java.util.ArrayList;
import java.util.List;

public class COPECipher extends CipherSpi implements EngineAutoBindable {

    public static final String ALGORITHM_NAME = "ChaoticOPE";

    private int opmode;

    private BigDecimal p;
    private int k = COPEAlgorithmParameterSpec.DEFAULT_K;

    private BigDecimal[] beta;
    private long[] b;

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
            this.p = BigDecimal.valueOf(raw.getP());

            SecureRandom random = new SecureRandom(raw.getSeed());

            b = new long[k + 1];
            beta = new BigDecimal[k];
            b[0] = 0;
            for (int i = 0; i < k; i++) {
                b[i + 1] = random.nextLong();
                beta[i] = p.divide(BigDecimal.valueOf(b[i + 1] - b[i]),  RoundingMode.HALF_UP);
            }

            for (int i = 0; i < k; i++) {
                System.out.println(beta[i]);
            }
            for (int i = 0; i < k + 1; i++) {
                System.out.println(b[i]);
            }

        } else throw new InvalidKeyException("The key used is not a FOPE Key");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof COPEAlgorithmParameterSpec))
            throw new InvalidAlgorithmParameterException();
        k = ((COPEAlgorithmParameterSpec) algorithmParameterSpec).getK();
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
            output = new byte[Long.BYTES];
        }
        try {
            engineUpdate(input, inputOffset, inputLen, output, 0);
            return output;
        } catch (ShortBufferException e) {
            // never thrown
            throw new ProviderException("Unexpected exception", e);
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        if (opmode == Cipher.ENCRYPT_MODE) {
            BigDecimal y = BigDecimal.valueOf(ByteBuffer.wrap(input).getDouble());

            List<BigDecimal> w = new ArrayList<>();
        } else if (opmode == Cipher.DECRYPT_MODE) {
        }

        return inputLen;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        return engineUpdate(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        return engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

}
