import crypto.GaloisJCE;
import crypto.algorithm.ppe.stott.StottCipher;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class Galois {
    public static void main(String[] args) {
        GaloisJCE.add();
        String algo = StottCipher.Prefix.ALGORITHM_NAME;
        try {
            byte[] x1 = new byte[]{0, 0, 0, 0};
            byte[] x2 = new byte[]{0, 20, 15, 20};

            KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
            SecretKey key = keyGenerator.generateKey();
            Cipher c = Cipher.getInstance(algo);

            System.out.println("Key-Size: " + key.getEncoded().length * 8);
            System.out.println("Key: " + new String(Base64.getEncoder().encode(key.getEncoded())));

            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted1 = c.doFinal(x1);
            byte[] encrypted2 = c.doFinal(x2);

            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted1 = c.doFinal(encrypted1);
            byte[] decrypted2 = c.doFinal(encrypted2);

            System.out.println("Value: " + Arrays.toString(x1));
            System.out.println("Encrypted: " + Arrays.toString(encrypted1));
            System.out.println("Decrypted: " + Arrays.toString(decrypted1));

            System.out.println("Value: " + Arrays.toString(x2));
            System.out.println("Encrypted: " + Arrays.toString(encrypted2));
            System.out.println("Decrypted: " + Arrays.toString(decrypted2));

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

    }
}

