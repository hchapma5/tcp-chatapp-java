package src.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * PasswordUtil is a utility class for password hashing and comparison.
 * It uses SHA-256 for hashing and Base64 for encoding.
 */
public class PasswordUtil {

    private static final int SALT_LENGTH = 16; // 16 bytes for salt

    /**
     * Generates a salt for hashing.
     * 
     * @return A Base64 encoded salt string.
     */
    private static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Hashes a password and automatically handles salt generation and encoding.
     * 
     * @param password The password to be hashed.
     * @return A combined salt and hash string.
     */
    public static String hashPassword(String password) {
        String salt = generateSalt();
        return hashAndCombine(password, salt);
    }

    /**
     * Compares a plaintext password with a stored hash and salt combination.
     * 
     * @param plaintextPassword The plaintext password to be compared.
     * @param storedHash        The stored hash and salt combination.
     * @return True if the plaintext password matches the stored hash, false
     *         otherwise.
     */
    public static boolean comparePassword(String plaintextPassword, String storedHash) {
        String salt = storedHash.substring(0, encodedSaltLength());
        String expectedHash = storedHash.substring(encodedSaltLength());
        String resultHash = hashAndCombine(plaintextPassword, salt).substring(encodedSaltLength());
        return resultHash.equals(expectedHash);
    }

    /**
     * Calculates the length of the encoded salt.
     * 
     * @return The length of the encoded salt.
     */
    private static int encodedSaltLength() {
        byte[] dummySalt = new byte[SALT_LENGTH];
        return Base64.getEncoder().encodeToString(dummySalt).length();
    }

    /**
     * Hashes a password with a given salt and returns a combined salt and hash
     * string.
     * 
     * @param password The password to be hashed.
     * @param salt     The salt to be used for hashing.
     * @return A combined salt and hash string.
     * @throws RuntimeException if the SHA-256 algorithm is not found.
     */
    private static String hashAndCombine(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(Base64.getDecoder().decode(salt));
            byte[] hashedPassword = md.digest(password.getBytes());
            return salt + Base64.getEncoder().encodeToString(hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash password", e);
        }
    }
}