import crypto.BraqueProvider;
import crypto.algorithm.ope.fope.FOPEAlgorithmParameterSpec;
import crypto.algorithm.ope.fope.FOPESecretKeySpec;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Braque {
    public static void main(String[] args) {
        BraqueProvider.add();

        String algo = "FOPE";
        try {
            int d = 16;
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
            FOPEAlgorithmParameterSpec parameterSpec = new FOPEAlgorithmParameterSpec(16, d);

            keyGenerator.init(parameterSpec);

            SecretKey key = keyGenerator.generateKey();

            Cipher c = Cipher.getInstance(algo);
            long x = 23136;

            c.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            byte[] encrypted = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x).array());

            c.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            byte[] decrypted = c.doFinal(encrypted);

            System.out.println("Value: " + x);
            System.out.println("Encrypted: " + ByteBuffer.wrap(encrypted).getLong());
            System.out.println("Decrypted: " + ByteBuffer.wrap(decrypted).getLong());
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }
}

