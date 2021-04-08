import crypto.GaloisProvider;
import crypto.algorithm.ppe.cryptopan.CryptoPanCipher;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class Galois {
    public static void main(String[] args) {
        GaloisProvider.add();

        String algo = CryptoPanCipher.ALGORITHM_NAME;
        try {
            String x = "ABCD";
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
            SecretKey key = keyGenerator.generateKey();

            System.out.println("Key-Size: " + key.getEncoded().length * 8);
            System.out.println("Key: " + new String(Base64.getEncoder().encode(key.getEncoded())));

            Cipher c = Cipher.getInstance(algo);

            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = c.doFinal(x.getBytes());

            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = c.doFinal(encrypted);

            System.out.println("Value: " + x);
            System.out.println("Encrypted: " + Arrays.toString(encrypted));
            System.out.println("Decrypted: " + new String(decrypted));

            x = "ABC";
            c.init(Cipher.ENCRYPT_MODE, key);
            encrypted = c.doFinal(x.getBytes());

            c.init(Cipher.DECRYPT_MODE, key);
            decrypted = c.doFinal(encrypted);

            System.out.println("Value: " + x);
            System.out.println("Encrypted: " + Arrays.toString(encrypted));
            System.out.println("Decrypted: " + new String(decrypted));

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

    }
}

