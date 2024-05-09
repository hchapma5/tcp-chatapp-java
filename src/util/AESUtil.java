package src.util;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Utility class for AES encryption and decryption using the GCM mode,
 * integrated with Diffie-Hellman
 * key agreement protocol for generating shared secrets.
 * Provides functionality to encrypt and decrypt data automatically handling the
 * IV, and also methods to generate and derive keys suitable for use with AES.
 */
public class AESUtil {

    private static final String DH_ALGORITHM = "DH";
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int AES_KEY_SIZE = 256;
    private static final int IV_SIZE = 12; // 96-bit IV for GCM

    /**
     * Generates a key pair using the Diffie-Hellman (DH) algorithm.
     * 
     * @return A DH KeyPair.
     * @throws NoSuchAlgorithmException If the DH algorithm is not available.
     */
    public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyPairGenerator.initialize(2048); // 2048-bit key size
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generates a shared secret using a private key and a public key encoded as
     * bytes.
     * 
     * @param privateKey     The private key to use in generating the shared secret.
     * @param publicKeyBytes The public key as bytes, to be used in the key
     *                       agreement.
     * @return A byte array containing the shared secret.
     * @throws NoSuchAlgorithmException If the DH algorithm is not available.
     * @throws InvalidKeySpecException  If the encoded key specification is invalid.
     * @throws InvalidKeyException      If the provided key is inappropriate for
     *                                  initializing this key agreement.
     */
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

    /**
     * Derives an AES key from a given shared secret.
     * 
     * @param sharedSecret The shared secret from which to derive the AES key.
     * @return A SecretKeySpec suitable for AES encryption.
     * @throws NoSuchAlgorithmException If the SHA-256 digest algorithm is not
     *                                  available.
     */
    public static SecretKey deriveAESKey(byte[] sharedSecret) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(sharedSecret);
        return new SecretKeySpec(keyBytes, 0, AES_KEY_SIZE / 8, "AES");
    }

    /**
     * Encrypts plaintext using AES/GCM/NoPadding.
     * Automatically generates and prepends the IV to the ciphertext.
     * 
     * @param plaintext The plaintext bytes to encrypt.
     * @param key       The AES key to use for encryption.
     * @return A Base64-encoded string containing the IV followed by the encrypted
     *         data.
     */
    public static String encrypt(String plaintext, SecretKey key) {
        try {
            // Convert plaintext string to bytes
            byte[] plaintextBytes = plaintext.getBytes();

            // Generate a new IV for each encryption
            byte[] iv = generateIV();

            // Get a Cipher instance for AES-GCM without padding.
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);

            // Create a specification for the GCM parameters
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            // Init the cipher with the key and IV
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

            // Encrypt the plaintext and compute an authentication tag
            byte[] encrypted = cipher.doFinal(plaintextBytes);

            // Combine IV and encrypted data
            byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
            System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);

            // Encode the IV and encrypted data with authentication tag as a Base64 string
            return Base64.getEncoder().encodeToString(encryptedWithIv);
        } catch (GeneralSecurityException e) {
            System.out.println("Error encrypting data: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypts ciphertext encrypted with AES/GCM/NoPadding.
     * Expects the IV to be prepended to the ciphertext.
     * 
     * @param ciphertextWithIv The Base64-encoded string containing the IV followed
     *                         by the encrypted data.
     * @param key              The AES key to use for decryption.
     * @return The decrypted plaintext as a string.
     */
    public static String decrypt(String ciphertextWithIv, SecretKey key) {
        try {
            // Decode the Base64 string to get the IV and encrypted data
            byte[] decodedInput = Base64.getDecoder().decode(ciphertextWithIv);

            // Extract the IV from the beginning of the decoded array
            byte[] iv = Arrays.copyOfRange(decodedInput, 0, IV_SIZE);

            // Extract the ciphertext
            byte[] ciphertext = Arrays.copyOfRange(decodedInput, IV_SIZE, decodedInput.length);

            // Get a Cipher instance for AES-GCM without padding.
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);

            // Create a specification for the GCM parameters
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            // Init the cipher with the key and IV
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

            // decrypt and verify the tag (throws AEADBadTagException)
            byte[] decryptedBytes = cipher.doFinal(ciphertext);

            // Convert the decrypted bytes to a string
            return new String(decryptedBytes);
        } catch (GeneralSecurityException e) {
            System.out.println("Error decrypting data: " + e.getMessage());
            return null;
        }
    }

    /**
     * Generates a secure random IV for use with AES/GCM encryption.
     * 
     * @return A byte array containing the IV.
     */
    private static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);
        return iv;
    }
}
