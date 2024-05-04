package src.server;

import java.util.UUID;
import src.util.PasswordUtil;

/**
 * User class
 * 
 * Represents a User with a username and password
 * The User is assigned a random UUID as an ID
 * The password is hashed using SHA-256 and a random salt
 * 
 */
public class User {

    public String id;
    public String username;
    private String passwordHash;

    /**
     * Create a new user with a username and password
     * 
     * @param username
     * @param password
     */
    public User(String username, String password) {
        if (!isValidUsername(username) || !isValidPassword(password)) {
            throw new IllegalArgumentException("Invalid username or password");
        }
        this.username = username;
        this.id = UUID.randomUUID().toString();
        this.passwordHash = PasswordUtil.hashPassword(password);
    }

    /**
     * Check if the password is valid
     * 
     * A valid password must:
     * - Be at least 8 characters long
     * - Contain at least one digit
     * - Contain at least one lowercase letter
     * - Contain at least one uppercase letter
     * - Contain at least one special character
     * - Not contain any whitespace
     * 
     * @param password
     * @return boolean
     */
    private boolean isValidPassword(String password) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*-_+=/])(?=\\S+$).{8,}$";
        return (password == null) ? false : password.matches(regex);
    }

    /**
     * Check if the username is valid
     * 
     * A valid username must:
     * - Be between 4 and 16 characters long
     * - Contain only alphanumeric characters
     * 
     * @param username
     * @return boolean
     */
    private boolean isValidUsername(String username) {
        String regex = "^[a-zA-Z0-9]{4,16}$";
        return (username == null) ? false : username.matches(regex);
    }

    /**
     * Check if the password is correct
     * 
     * @param password
     * @return
     */
    public boolean checkPassword(String password) {
        return PasswordUtil.comparePassword(password, this.passwordHash);
    }

    // Main method for testing the User class and hashed password
    public static void main(String[] args) {
        User user = new User("testuser", "Password123!");
        System.out.println("User ID: " + user.id);
        System.out.println("Username: " + user.username);
        System.out.println("Password hash: " + user.passwordHash);
        System.out.println("Password check: " + user.checkPassword("Password123!"));
    }

}
