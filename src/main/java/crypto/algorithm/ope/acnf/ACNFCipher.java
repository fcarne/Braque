package crypto.algorithm.ope.acnf;

import crypto.EngineAutoBindable;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class ACNFCipher extends CipherSpi implements EngineAutoBindable {

    public static final String ALGORITHM_NAME = "ArithmeticCoding";

    private int opmode;

    @Override
    public String getBind() {
        return "Cipher." + ALGORITHM_NAME;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        //TODO
        throw new NoSuchAlgorithmException("FOPE does not support different modes");
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        //TODO
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
        if (key instanceof ACNFSecretKeySpec) {
        } else throw new InvalidKeyException("The key used is not a FOPE Key");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
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
            output = new byte[0];
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
