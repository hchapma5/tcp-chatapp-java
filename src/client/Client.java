package src.client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ConnectException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import src.util.AESUtil;

/**
 * The Client class represents a client in a TCP chat application.
 * It is responsible for establishing a connection with the server,
 * sending and receiving messages, and handling user commands.
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
        } catch (Exception e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void sendMessage(String message) {
        try {
            String ciphertext = AESUtil.encrypt(message, secretKey);
            bufferedWriter.write(ciphertext);
            bufferedWriter.newLine();
            bufferedWriter.flush();
        } catch (Exception e) {
            // TODO: handle exception
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public String readEncryptedMessage() {
        try {
            return AESUtil.decrypt(bufferedReader.readLine(), secretKey);
        } catch (Exception e) {
            // TODO: handle exception
            closeEverything(socket, bufferedReader, bufferedWriter);
            return null;
        }

    }

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
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
        }
    }

    public void displayCommandMenu() {
        System.out.println("Choose a command:");
        System.out.println("(1): Send a message");
        System.out.println("(2): Read messages");
        System.out.println("(3): Disconnect");
    }

    public static boolean isValidCommand(String command) {
        return new String("123").contains(command);
    }

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
                    sendMessage("COMPOSE " + recipient);
                    String messageToSpend = scanner.nextLine();
                    sendMessage(messageToSpend);
                }
                case "2" -> {
                    sendMessage("READ");
                }
                case "3" -> {
                    sendMessage("EXIT");
                }
            }
        }
    }

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
                        // TODO: handle exception
                        closeEverything(socket, bufferedReader, bufferedWriter);
                    }
                }
            }
        }).start();
    }

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
            System.exit(0); // exit the program
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void displayAuthCommands() {
        System.out.println("Choose a command:");
        System.out.println("(1): Login");
        System.out.println("(2): Register");
        System.out.println("(3): Exit");
    }

    private boolean isValidPassword(String password) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*-_+=/])(?=\\S+$).{8,}$";
        return (password == null) ? false : password.matches(regex);
    }

    private boolean isValidUsername(String username) {
        String regex = "^[a-zA-Z0-9]{4,16}$";
        return (username == null) ? false : username.matches(regex);
    }

    public void handleAuthentication(Scanner scanner, String command)
            throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        switch (command) {
            case "1" -> {
                System.out.print("Enter username: ");
                String username = scanner.nextLine();
                System.out.print("Enter password: ");
                String password = scanner.nextLine();
                sendMessage("LOGIN " + username + ":" + password);
            }
            case "2" -> {
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
                sendMessage("REGISTER " + username + ":" + password);
            }
            case "3" -> {
                sendMessage("EXIT");
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