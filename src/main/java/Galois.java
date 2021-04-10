import crypto.GaloisProvider;
import crypto.algorithm.ppe.cryptopan.CryptoPanAlgorithmParameterSpec;
import crypto.algorithm.ppe.cryptopan.CryptoPanCipher;

import javax.crypto.*;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class Galois {
    public static void main(String[] args) {
        GaloisProvider.add();

        String algo = CryptoPanCipher.Prefix.ALGORITHM_NAME;
        try {
            InetAddress x1 = InetAddress.getByName("2001:0db8:85a3:0000:1319:8a2e:0370:7344");
            InetAddress x2 = InetAddress.getByName("2001:0db8:85a3:0000:1319:8a2e:0370:3434");
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
            SecretKey key = keyGenerator.generateKey();

            System.out.println("Key-Size: " + key.getEncoded().length * 8);
            System.out.println("Key: " + new String(Base64.getEncoder().encode(key.getEncoded())));

            Cipher c = Cipher.getInstance(algo);

            CryptoPanAlgorithmParameterSpec parameterSpec = new CryptoPanAlgorithmParameterSpec(16);

            c.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            byte[] encrypted1 = c.doFinal(x1.getAddress());
            byte[] encrypted2 = c.doFinal(x2.getAddress());

            c.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            byte[] decrypted1 = c.doFinal(encrypted1);
            byte[] decrypted2 = c.doFinal(encrypted2);

            System.out.println("Value: " + x1.getHostAddress());
            System.out.println("Encrypted: " + InetAddress.getByAddress(encrypted1).getHostAddress());
            System.out.println("Decrypted: " + InetAddress.getByAddress(decrypted1).getHostAddress());

            System.out.println("Value: " + x2.getHostAddress());
            System.out.println("Encrypted: " + InetAddress.getByAddress(encrypted2).getHostAddress());
            System.out.println("Decrypted: " + InetAddress.getByAddress(decrypted2).getHostAddress());

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | UnknownHostException e) {
            e.printStackTrace();
        }

    }
}

