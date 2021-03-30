import crypto.GaloisProvider;
import crypto.algorithm.ope.fope.FOPECipher;

import javax.crypto.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Galois {
    public static void main(String[] args) {
        GaloisProvider.add();

        String algo = FOPECipher.ALGORITHM_NAME;
        try {
            int d = 8;
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);

            SecretKey key = keyGenerator.generateKey();
            System.out.println("Key-Size: " + key.getEncoded().length * 8);
            System.out.println("Key: " + new String(Base64.getEncoder().encode(key.getEncoded())));

            Cipher c = Cipher.getInstance(algo);

            long x = 240;

            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = c.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(x).array());

            c.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = c.doFinal(encrypted);

            System.out.println("Value: " + x);
            System.out.println("Encrypted: " + new BigInteger(encrypted));
            System.out.println("Decrypted: " + ByteBuffer.wrap(decrypted).getLong());
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

    }
}

