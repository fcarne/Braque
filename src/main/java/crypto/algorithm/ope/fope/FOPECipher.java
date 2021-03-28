package crypto.algorithm.ope.fope;

import crypto.EngineAutoBindable;

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

public class FOPECipher extends CipherSpi implements EngineAutoBindable {

    private int opmode;

    private byte[] kBytes;

    private int d = FOPEAlgorithmParameterSpec.DEFAULT_D;

    private long[] infLimitF;
    private long[] supLimitF;

    @Override
    public String getBind() {
        return "Cipher.FOPE";
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("FOPE does not support different modes");
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("FOPE does not support different padding mechanisms");
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
        if (key instanceof FOPESecretKeySpec) {
            FOPESecretKeySpec.Raw raw = ((FOPESecretKeySpec) key).decodeKey();

            BigDecimal alpha = BigDecimal.valueOf(raw.getAlpha());
            BigDecimal beta = BigDecimal.valueOf(raw.getBeta());
            BigDecimal n = BigDecimal.valueOf((raw.getN()));
            BigDecimal e = BigDecimal.valueOf(raw.getE());

            infLimitF = new long[d + 1];
            supLimitF = new long[d + 1];

            for (int j = 0; j <= d; j++) {
                BigDecimal factor = n.multiply(e.pow(j));
                infLimitF[j] = alpha.multiply(factor).setScale(0, RoundingMode.FLOOR).longValue();
                supLimitF[j] = beta.multiply(factor).setScale(0, RoundingMode.CEILING).longValue();
            }

            kBytes = ByteBuffer.allocate(Long.BYTES).putLong(raw.getK()).array();

        } else throw new InvalidKeyException("The key used is not a FOPE Key");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (algorithmParameterSpec instanceof FOPEAlgorithmParameterSpec) {
            d = ((FOPEAlgorithmParameterSpec) algorithmParameterSpec).getD();
        } else throw new InvalidAlgorithmParameterException();
        engineInit(opmode, key, secureRandom);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException {
        engineInit(opmode, key, secureRandom);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] output = new byte[inputLen];
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
        ByteBuffer plaintext;
        ByteBuffer ciphertext;
        int limit;
        if (opmode == Cipher.ENCRYPT_MODE) {
            plaintext = ByteBuffer.wrap(input);
            limit = plaintext.remaining() / Long.BYTES;

            ciphertext = ByteBuffer.allocate(plaintext.remaining());

            for (int i = 0; i < limit; i++) {
                long x = plaintext.getLong();

                long cipher = f(0, 0);
                for (int j = 1; j <= d; j++) {
                    long xI = (x >> (d - j)) & 1;
                    cipher += (2 * xI - 1) * f(j, x);
                }

                ciphertext.putLong(cipher);
            }
            ciphertext.position(0);

            System.arraycopy(ciphertext.array(), 0, output, 0, inputLen);
        } else if (opmode == Cipher.DECRYPT_MODE) {
            ciphertext = ByteBuffer.wrap(input);
            limit = ciphertext.remaining() / Long.BYTES;

            plaintext = ByteBuffer.allocate(ciphertext.remaining());

            for (int i = 0; i < limit; i++) {
                long c = ciphertext.getLong();

                long a = f(0, 0);
                long plain = c < a ? 0 : 1L << (d - 1);

                for (int j = 2; j <= d; j++) {
                    long xI = (plain >> (d - j + 1)) & 1;
                    a += (2 * xI - 1) * f(j - 1, plain);
                    if (c >= a) {
                        plain |= 1L << (d - j);
                    }
                }

                long x0 = plain & 1;
                a += (2 * x0 - 1) * f(d, plain);
                if (c != a) plain = Long.MIN_VALUE;

                plaintext.putLong(plain);
            }

            System.arraycopy(plaintext.array(), 0, output, 0, inputLen);
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

    private long f(int i, long x) {
        try {
            // Include only i most significant bits
            int shift = d - i;
            x = x >> shift << shift;

            // Calculate hash
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(kBytes);
            md.update(ByteBuffer.allocate(Long.BYTES).putLong(x).array());

            byte[] hash = md.digest();

            // Convert to big integer
            BigInteger bi = new BigInteger(hash);

            BigInteger modulus = BigInteger.valueOf(supLimitF[i] - infLimitF[i]);

            // Calculate function value
            return  bi.mod(modulus).add(BigInteger.valueOf(infLimitF[i])).longValue();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return -1;
        }
    }
}
