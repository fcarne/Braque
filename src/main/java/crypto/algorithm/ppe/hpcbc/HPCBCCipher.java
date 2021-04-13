package crypto.algorithm.ppe.hpcbc;

import crypto.algorithm.GaloisCipher;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;

public class HPCBCCipher extends GaloisCipher {

    protected static final String ALGORITHM_NAME = "HPCBC";

    @Override
    public String getBind() {
        return "Cipher." + ALGORITHM_NAME;
    }

    @Override
    protected void engineInit(int i, Key key, SecureRandom secureRandom) throws InvalidKeyException {

    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return 0;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        return 0;
    }
}
