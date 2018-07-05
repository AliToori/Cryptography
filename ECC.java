package aliecc;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

/**
 *
 * @author Ali
 */
public class AliECC {
    
    // Generates and returns Ellipc Curve KeyPair
    public static KeyPair generateECKeys(String algorithm, String provider) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
            ECGenParameterSpec eCGenParameterSpec = new ECGenParameterSpec("secp256r1"); 
            keyPairGenerator.initialize(eCGenParameterSpec);
            //KeyPair keyPair = keyPairGenerator.genKeyPair();
            keyPairGenerator.initialize(eCGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return keyPair;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }
   
    public static void main(String args[]) {
        try {
            Provider providers[] = Security.getProviders();
            System.out.println("Agorithm Providers and their information ");
            for (int i = 0; i<providers.length;i++) {  
                System.out.println("Agorithm Provider: "+providers[i].getName());
                System.out.println("Agorithm Provider information: "+providers[i].getInfo());
            }
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            //parameters: secp256r1 [NIST P-256]
            ECGenParameterSpec eCGenParameterSpec = new ECGenParameterSpec("secp256r1"); 
            keyPairGenerator.initialize(eCGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Provider provider = keyPairGenerator.getProvider();
            String  algorithm = keyPairGenerator.getAlgorithm();
            System.out.println("KeyPair generation");
            System.out.println("We are using, algorithm: "+algorithm+" from provider: "+provider);
            System.out.println("Generated Keys: ");
            //Getting Public Key from keyPair
            PublicKey publicKey = keyPair.getPublic();
            // Getting length of the Public key
            int publicKeyLength = publicKey.toString().length();
            System.out.println("Size of the public key is: "+publicKeyLength);
            System.out.println("The Public key is: "+publicKey.toString());

            // Getting private key fro kayPair
            PrivateKey privateKey = keyPair.getPrivate();
            // Getting length of the Private key
            int privateKeyLength = privateKey.toString().length();
            System.out.println("Size of the private key is: "+privateKeyLength);
             System.out.println("The private key is: "+privateKey.toString());
             
            // Elliptic Curve Integrated Encryption Scheme
            Cipher cipher = Cipher.getInstance(algorithm, provider);
            System.out.println("Cipher Algorithm: "+cipher.getAlgorithm());
            System.out.println("Cipher Algorithm Provider: " + cipher.getProvider());
            System.out.println("Cipher Block Size: "+cipher.getBlockSize());
            // Encryption mode
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // Creatin Plaintext/Ciphertext files
            String plainTextFile = "plaintext.txt";
            String cipherTextFile = "ciphertextECIES.txt";

            byte[] block = new byte[64];
            FileInputStream fis = new FileInputStream(plainTextFile);
            FileOutputStream fos = new FileOutputStream(cipherTextFile);
            CipherOutputStream cos = new CipherOutputStream(fos, cipher);
            int i;
            // Writing ciphertext to the ciphertextECIES file
            while ((i = fis.read(block)) != -1) {
                cos.write(block, 0, i);
            }
            cos.close();
            String plainTextAgainFile = "plaintextagainECIES.txt";
            // Getting decryption mode
            cipher.init(Cipher.DECRYPT_MODE, privateKey, eCGenParameterSpec);
            fis = new FileInputStream(cipherTextFile);
            CipherInputStream cis = new CipherInputStream(fis, cipher);
            fos = new FileOutputStream(plainTextAgainFile);
            // Writing (decrypted)plaintext to the plaintext file
            while ((i = cis.read(block)) != -1) {
                fos.write(block, 0, i);
            }
            fos.close();
        } 
catch (Exception e) {
    System.out.print(e); 
        }
    }
}
