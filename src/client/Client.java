package src.client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ConnectException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.SecretKey;

import src.util.AESUtil;

/**
 * The `Client` class represents a client in a TCP chat application.
 * It handles the communication between the client and the server,
 * including sending and receiving encrypted messages, performing
 * Diffie-Hellman key exchange, and handling user commands.
 */
public class Client {

    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private SecretKey secretKey;

    public Client(Socket socket) {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (IOException e) {
            System.err.println("Error creating client: " + e.getMessage());
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    /**
     * Performs a Diffie-Hellman key exchange with the server.
     * This method generates a key pair, sends the public key to the server,
     * receives the server's public key, generates a shared secret,
     * and derives an AES key from the shared secret.
     * 
     * @throws IOException              if an I/O error occurs during the key
     *                                  exchange
     * @throws GeneralSecurityException if a security error occurs during the key
     *                                  exchange
     */
    public void DiffieHellmanKeyExchange() {
        try {
            KeyPair keyPair = AESUtil.generateDHKeyPair();
            // Send public key to server
            String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            bufferedWriter.write(publicKey);
            bufferedWriter.newLine();
            bufferedWriter.flush();
            // Wait to receive public key from server
            byte[] serverPublicKey = Base64.getDecoder().decode(bufferedReader.readLine()); // convert String to
            byte[] sharedSecret = AESUtil.generateSharedSecret(keyPair.getPrivate(),
                    serverPublicKey);
            this.secretKey = AESUtil.deriveAESKey(sharedSecret);
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("An error occured during key exchange. Exiting...");
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    /**
     * Sends an encrypted message to the server.
     *
     * @param message the message to be sent
     */
    public void sendEncryptedMessage(String message) {
        try {
            // Check connection before sending message
            if (socket.isClosed()) {
                System.err.println("Connection to server is closed. Exiting...");
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
            String ciphertext = AESUtil.encrypt(message, secretKey);
            bufferedWriter.write(ciphertext);
            bufferedWriter.newLine();
            bufferedWriter.flush();
        } catch (IOException e) {
            System.err.println("An error occured sending message to server");
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    /**
     * Reads an encrypted message from the server and decrypts it using the provided
     * secret key.
     * If the server sends a null message, it closes the connection and returns
     * null.
     *
     * @return The decrypted message from the server, or null if the server sends a
     *         null message.
     */
    public String readEncryptedMessage() {
        try {
            String message = AESUtil.decrypt(bufferedReader.readLine(), secretKey);
            if (message == null)
                return null;
            // If server sends null, close everything (EXIT command)
            return message;
        } catch (IOException e) {
            System.err.println("An error occured decrypting server message");
            closeEverything(socket, bufferedReader, bufferedWriter);
            return null;
        }
    }

    /**
     * Displays the authentication commands for the client.
     * The user can choose between login, register, or exit.
     */
    public void displayAuthCommands() {
        System.out.println("Choose a command:");
        System.out.println("(1): Login");
        System.out.println("(2): Register");
        System.out.println("(3): Exit");
    }

    /**
     * Checks if a command is valid.
     *
     * @param command the command to be checked
     * @return true if the command is valid, false otherwise
     */
    public static boolean isValidCommand(String command) {
        return new String("123").contains(command);
    }

    /**
     * Checks if a password is valid.
     *
     * @param password the password to be checked
     * @return true if the password is valid, false otherwise
     */
    private boolean isValidPassword(String password) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*-_+=/])(?=\\S+$).{8,}$";
        return (password == null) ? false : password.matches(regex);
    }

    /**
     * Checks if the given username is valid.
     *
     * @param username the username to be checked
     * @return true if the username is valid, false otherwise
     */
    private boolean isValidUsername(String username) {
        String regex = "^[a-zA-Z0-9]{4,16}$";
        return (username == null) ? false : username.matches(regex);
    }

    /**
     * Handles the authentication process for the client.
     *
     * @param scanner The scanner object used for user input.
     * @param command The command selected by the user.
     */
    public void handleAuthentication(Scanner scanner, String command) {
        switch (command) {
            case "1" -> { // LOGIN
                System.out.print("Enter username: ");
                String username = scanner.nextLine();
                System.out.print("Enter password: ");
                String password = scanner.nextLine();
                sendEncryptedMessage("LOGIN " + username + ":" + password);
            }
            case "2" -> { // REGISTER
                System.out.print("Enter username: ");
                String username = scanner.nextLine();
                // Validate username
                while (!isValidUsername(username)) {
                    System.out.println("Invalid username. Try again.");
                    System.out.print("Enter username: ");
                    username = scanner.nextLine();
                }
                System.out.print("Enter password: ");
                String password = scanner.nextLine();
                // Validate password
                while (!isValidPassword(password)) {
                    System.out.println("Invalid password. Try again.");
                    System.out.print("Enter password: ");
                    password = scanner.nextLine();
                }
                sendEncryptedMessage("REGISTER " + username + ":" + password);
            }
            case "3" -> { // EXIT
                sendEncryptedMessage("EXIT");
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        }
        String response = readEncryptedMessage();
        if (response.startsWith("SERVER")) {
            System.out.println(response);
            handleAuthentication(scanner, command);
            return;
        }
        String username = response.split(":")[0];
        String inboxCount = response.split(":")[1];
        System.out.println("Welcome, " + username + "!");
        System.out.println("You have " + inboxCount + " unread messages.");
        displayCommandMenu();
    }

    /**
     * Displays the command menu for the client.
     * The menu includes options to send a message, read messages, and disconnect.
     */
    public void displayCommandMenu() {
        System.out.println("Choose a command:");
        System.out.println("(1): Send a message");
        System.out.println("(2): Read messages");
        System.out.println("(3): Disconnect");
    }

    /**
     * Handles user commands in the chat client.
     *
     * @param scanner The scanner object used to read user input.
     */
    public void commandHandler(Scanner scanner) {
        while (!socket.isClosed()) {
            String command = scanner.nextLine();
            // handle invalid commands
            while (!isValidCommand(command)) {
                System.out.println("Invalid command. Try again.");
                displayCommandMenu();
                command = scanner.nextLine();
            }
            switch (command) {
                case "1" -> {
                    System.out.println("Enter the username of the recipient: ");
                    String recipient = scanner.nextLine();
                    // Make sure recipient is a valid username
                    while (!recipient.matches("^[^\\s]+$")) {
                        System.out.println("Invalid username: Try again with no spaces.");
                        recipient = scanner.nextLine();
                    }
                    System.out.println("Enter your message: ");
                    sendEncryptedMessage("COMPOSE " + recipient);
                    String messageToSpend = scanner.nextLine();
                    sendEncryptedMessage(messageToSpend);
                }
                case "2" -> {
                    sendEncryptedMessage("READ");
                }
                case "3" -> {
                    sendEncryptedMessage("EXIT");
                }
            }
        }
    }

    /**
     * Listens for incoming messages from the server.
     * This method runs in a separate thread to continuously receive messages from
     * the server.
     * If the server sends a null message, it closes the connection and terminates
     * the client.
     * Any exceptions that occur during the message receiving process will also
     * result in closing the connection.
     */
    public void listen() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String messageFromServer;
                while (socket.isConnected()) {
                    try {
                        messageFromServer = readEncryptedMessage();
                        // If server sends null, close everything (EXIT command)
                        if (messageFromServer == null)
                            closeEverything(socket, bufferedReader, bufferedWriter);
                        // Read messages from server
                        System.out.println(messageFromServer);
                        displayCommandMenu();
                    } catch (Exception e) {
                        closeEverything(socket, bufferedReader, bufferedWriter);
                    }
                }
            }
        }).start();
    }

    /**
     * Closes the socket, BufferedReader, and BufferedWriter, and exits the program.
     * 
     * @param socket         the Socket object to be closed
     * @param bufferedReader the BufferedReader object to be closed
     * @param bufferedWriter the BufferedWriter object to be closed
     */
    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
        try {
            if (bufferedReader != null) {
                bufferedReader.close();
            }
            if (bufferedWriter != null) {
                bufferedWriter.close();
            }
            if (socket != null) {
                socket.close();
            }
            System.exit(0);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * The entry point of the client application.
     * 
     * @param args the command line arguments. The first argument should be the
     *             hostname of the server, and the second argument should be the
     *             port number.
     */
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java Client <hostname> <port>");
            return; // exit if no host or port provided
        }
        try {
            String hostname = args[0];
            int port = Integer.parseInt(args[1]);

            // Connect client to server
            Socket socket = new Socket(hostname, port);
            Client client = new Client(socket);

            // Perform Diffie-Hellman key exchange
            client.DiffieHellmanKeyExchange();

            // Handle client authentication
            Scanner scanner = new Scanner(System.in);
            client.displayAuthCommands();
            String command = scanner.nextLine();

            // handle invalid commands
            while (!isValidCommand(command)) {
                System.out.println("Invalid command. Try again.");
                client.displayAuthCommands();
                command = scanner.nextLine();
            }
            client.handleAuthentication(scanner, command);

            // Send & Receive messages
            client.listen();
            client.commandHandler(scanner);

        } catch (NumberFormatException e) {
            System.out.println("Invalid port number. Please try again.");
        } catch (ConnectException e) {
            System.out.println("Connection refused. Server may be down.");
        } catch (UnknownHostException e) {
            System.out.println("Unknown host. Please try again.");
        } catch (IOException e) {
            System.out.println("Failed to connect to server. Please try again.");
        } catch (Exception e) {
            System.out.println("An error occurred during encryption. Please try again.");
        }
    }

}