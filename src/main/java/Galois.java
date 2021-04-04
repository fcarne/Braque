import crypto.GaloisProvider;
import crypto.algorithm.ope.fope.FOPEAlgorithmParameterSpec;
import crypto.algorithm.ope.fope.FOPECipher;
import crypto.algorithm.ope.gacd.GACDAlgorithmParameterSpec;
import crypto.algorithm.ope.gacd.GACDCipher;
import crypto.algorithm.ope.tym.TYMAlgorithmParameterSpec;
import crypto.algorithm.ope.tym.TYMCipher;
import crypto.algorithm.ope.tym.TYMSecretKeySpec;

import javax.crypto.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class Galois {
    public static void main(String[] args) {
        GaloisProvider.add();

        String algo = TYMCipher.ALGORITHM_NAME;
        try {
            long x = 240;
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
            SecretKey key = keyGenerator.generateKey();

            System.out.println("Key-Size: " + key.getEncoded().length * 8);
            System.out.println("Key: " + new String(Base64.getEncoder().encode(key.getEncoded())));

            Cipher c = Cipher.getInstance(algo);

            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = new byte[0];

            long start = System.currentTimeMillis();
            for (int i = 0; i < 1500; i++) {
                encrypted = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x).array());
            }
            System.out.println(Arrays.toString(encrypted));
            System.out.println("TIME: " + (System.currentTimeMillis() - start + "ms"));

            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = c.doFinal(encrypted);

            System.out.println("Value: " + x);
            System.out.println("Decrypted: " + ByteBuffer.wrap(decrypted).getLong());

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

    }
}

