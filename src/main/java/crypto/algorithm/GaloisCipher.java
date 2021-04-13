package crypto.algorithm;

import crypto.EngineAutoBindable;

import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public abstract class GaloisCipher extends CipherSpi implements EngineAutoBindable {
    protected int opMode;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("Cipher mode: " + mode + " not found");
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("Padding: " + padding + " not implemented");
    }

    @Override
    protected abstract void engineInit(int i, Key key, SecureRandom secureRandom) throws InvalidKeyException;

    @Override
    protected void engineInit(int opMode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opMode, key, secureRandom);
    }

    @Override
    protected void engineInit(int opMode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException {
        engineInit(opMode, key, secureRandom);
    }

    @Override
    protected abstract int engineGetOutputSize(int inputLen);

    @Override
    protected int engineGetBlockSize() {
        return 1;
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
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] output = new byte[engineGetOutputSize(inputLen)];
        engineUpdate(input, inputOffset, inputLen, output, 0);
        return output;
    }

    @Override
    protected abstract int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset);

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        return engineUpdate(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        return engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

    protected static byte[] getKeyBytes(Key key) throws InvalidKeyException {
        if (key == null) throw new InvalidKeyException("No key given");

        if (!"RAW".equalsIgnoreCase(key.getFormat())) throw new InvalidKeyException("Wrong format: RAW bytes needed");

        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) throw new InvalidKeyException("RAW key bytes missing");

        return keyBytes;
    }

}
