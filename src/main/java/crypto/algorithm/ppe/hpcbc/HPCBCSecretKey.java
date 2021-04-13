package crypto.algorithm.ppe.hpcbc;

import javax.crypto.SecretKey;
public class HPCBCSecretKey implements SecretKey {

    @Override
    public String getAlgorithm() {
        return HPCBCCipher.ALGORITHM_NAME;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }
}
