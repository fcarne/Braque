import crypto.GaloisProvider;
import crypto.algorithm.ope.fope.FOPECipher;
import crypto.algorithm.ope.gacd.GACDCipher;
import crypto.algorithm.ope.tym.TYMCipher;
import crypto.algorithm.ope.piore.PIORECipher;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Galois {
    public static void main(String[] args) {
        GaloisProvider.add();

        String algo = FOPECipher.ALGORITHM_NAME;
        try {
            long x = 240;
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
            SecretKey key = keyGenerator.generateKey();

            System.out.println("Key-Size: " + key.getEncoded().length * 8);
            System.out.println("Key: " + new String(Base64.getEncoder().encode(key.getEncoded())));

            Cipher c = Cipher.getInstance(algo);

            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x).array());

            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = c.doFinal(encrypted);

            System.out.println("Value: " + x);
            System.out.println("Decrypted: " + ByteBuffer.wrap(decrypted).getLong());

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

    }
}

