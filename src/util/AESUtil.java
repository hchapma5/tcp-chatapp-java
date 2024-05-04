package src.util;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AESUtil {

    private static final String DH_ALGORITHM = "DH";
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int AES_KEY_SIZE = 256;

    public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] generateSharedSecret(PrivateKey privateKey, byte[] publicKeyBytes)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        KeyFactory keyFactory = KeyFactory.getInstance(DH_ALGORITHM);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

        KeyAgreement keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        return keyAgreement.generateSecret();
    }

    public static SecretKey deriveAESKey(byte[] sharedSecret) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(sharedSecret);
        return new SecretKeySpec(keyBytes, 0, AES_KEY_SIZE / 8, "AES");
    }

    public static byte[] encryptAES(byte[] plaintext, SecretKey key, byte[] iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        return cipher.doFinal(plaintext);
    }

    public static byte[] decryptAES(byte[] ciphertext, SecretKey key, byte[] iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        return cipher.doFinal(ciphertext);
    }

    public static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12]; // 96-bit IV for GCM
        random.nextBytes(iv);
        return iv;
    }

    // Main file to test the AESUtil class
    public static void main(String[] args) {
        try {
            // Generate key pairs for two clients
            KeyPair keyPair1 = AESUtil.generateDHKeyPair();
            KeyPair keyPair2 = AESUtil.generateDHKeyPair();

            System.out.println(
                    "Client A: Public Key = " + Base64.getEncoder().encodeToString(keyPair1.getPublic().getEncoded()));
            System.out.println(
                    "Client B: Public Key = " + Base64.getEncoder().encodeToString(keyPair2.getPublic().getEncoded()));

            // Generate shared secrets
            byte[] sharedSecret1 = AESUtil.generateSharedSecret(keyPair1.getPrivate(),
                    keyPair2.getPublic().getEncoded());
            byte[] sharedSecret2 = AESUtil.generateSharedSecret(keyPair2.getPrivate(),
                    keyPair1.getPublic().getEncoded());

            System.out.println("Client A Shared Secret = " + Base64.getEncoder().encodeToString(sharedSecret1));
            System.out.println("Client B Shared Secret = " + Base64.getEncoder().encodeToString(sharedSecret2));

            // Derive AES keys from shared secrets
            SecretKey key1 = AESUtil.deriveAESKey(sharedSecret1);
            SecretKey key2 = AESUtil.deriveAESKey(sharedSecret2);

            System.out.println("Client A AES Key = " + Base64.getEncoder().encodeToString(key1.getEncoded()));
            System.out.println("Client B AES Key = " + Base64.getEncoder().encodeToString(key2.getEncoded()));

            // Generate IVs for AES encryption
            byte[] iv1 = AESUtil.generateIV();
            byte[] iv2 = AESUtil.generateIV();

            System.out.println("Client A IV = " + Base64.getEncoder().encodeToString(iv1));
            System.out.println("Client B IV = " + Base64.getEncoder().encodeToString(iv2));

            // Encrypt a plaintext message
            byte[] plaintext = "Hello, world!".getBytes();
            byte[] ciphertext1 = AESUtil.encryptAES(plaintext, key1, iv1);
            byte[] ciphertext2 = AESUtil.encryptAES(plaintext, key2, iv2);

            System.out.println("Ciphertext 1 = " + Base64.getEncoder().encodeToString(ciphertext1));
            System.out.println("Ciphertext 2 = " + Base64.getEncoder().encodeToString(ciphertext2));

            // Decrypt the ciphertext
            byte[] decrypted1 = AESUtil.decryptAES(ciphertext1, key2, iv1);
            byte[] decrypted2 = AESUtil.decryptAES(ciphertext2, key1, iv2);

            System.out.println("Decrypted 1 = " + new String(decrypted1));
            System.out.println("Decrypted 2 = " + new String(decrypted2));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
