package src.server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Queue;
import java.sql.Timestamp;
import javax.crypto.SecretKey;
import src.util.AESUtil;

/**
 * The `ClientHandler` class represents a handler for each client connected to
 * the server.
 * It implements the `Runnable` interface to allow concurrent handling of
 * multiple clients.
 * 
 * The `ClientHandler` class is responsible for handling client login, sending
 * and receiving messages,
 * and managing client connections.
 * 
 * The class maintains a list of connected clients and a message storage for
 * each client.
 * 
 * @param socket         The socket associated with the client connection.
 * @param bufferedReader The `BufferedReader` used for reading client input.
 * @param bufferedWriter The `BufferedWriter` used for writing server responses
 *                       to the client.
 */
public class ClientHandler implements Runnable {

    public static ArrayList<ClientHandler> clients = new ArrayList<>();
    public static ArrayList<User> users = new ArrayList<>();
    public static HashMap<String, Queue<String>> clientMessages = new HashMap<>();

    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private User user;
    private SecretKey secretKey;

    public ClientHandler(Socket socket) {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (IOException e) {
            System.out.println("Error creating client handler: " + e.getMessage());
            closeEverything(socket, bufferedReader, bufferedWriter);
        }

    }

    /**
     * Performs a Diffie-Hellman key exchange with the client.
     * This method generates a key pair, receives the client's public key,
     * sends the server's public key to the client, and generates a shared secret
     * key.
     * The shared secret key is used to derive an AES key for encryption and
     * decryption.
     * 
     * @throws IOException              if an I/O error occurs during the key
     *                                  exchange process.
     * @throws GeneralSecurityException if a security error occurs during the key
     *                                  exchange process.
     */
    public void DiffieHellmanKeyExchange() {
        try {
            KeyPair keyPair = AESUtil.generateDHKeyPair();
            // Receive public key from client
            byte[] clientPublicKey = Base64.getDecoder().decode(bufferedReader.readLine());
            // Send public key to client
            bufferedWriter.write(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            bufferedWriter.newLine();
            bufferedWriter.flush();
            // Generate shared secret
            byte[] sharedSecret = AESUtil.generateSharedSecret(keyPair.getPrivate(),
                    clientPublicKey);
            this.secretKey = AESUtil.deriveAESKey(sharedSecret);
        } catch (IOException | GeneralSecurityException e) {
            sendServerMessage(MessageType.ERROR, "An error occured during key exchange. Exiting...");
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    /**
     * Handles the authentication process for the client.
     * Reads the command sent by the client and performs the necessary actions based
     * on the command.
     * If the command is a valid LOGIN command, it checks the username and password
     * provided by the client.
     * If the command is a valid REGISTER command, it creates a new user with the
     * provided username and password.
     * Sends appropriate messages to the client based on the outcome of the
     * authentication process.
     * If the authentication is successful, sends the username and the number of
     * messages in the client's inbox.
     * Closes the connection if an invalid command is received or if the user
     * disconnects.
     */
    public void handleAuthentication() {
        try {
            String command = readEncryptedMessage();
            if (command != null && command.matches("^LOGIN\\s\\S+:\\S+$")) {
                String username = command.substring(6).split(":")[0];
                String password = command.substring(6).split(":")[1];
                clients.add(this); // add this connection
                // Find user in users by username
                this.user = users.stream().filter(u -> u.username.equals(username)).findFirst().orElse(null);
                // If user not found, send invalid login message
                if (user == null) {
                    sendServerMessage(MessageType.INFO, "Invalid username, please try again.");
                    return;
                }
                // Check if password is correct
                if (!user.checkPassword(password)) {
                    sendServerMessage(MessageType.INFO, "Invalid password, please try again.");
                    return;
                }
                // Check if User already logged in
                if (clients.stream().anyMatch(c -> c.user.username.equals(username) && c.user.isLoggedIn())) {
                    sendServerMessage(MessageType.INFO, "User already logged in, please try again.");
                    return;
                }
                System.out.println("Successfully logged in user: " + user.username);
            } else if (command != null && command.matches("^REGISTER\\s\\S+:\\S+$")) {
                String username = command.substring(9).split(":")[0];
                String password = command.substring(9).split(":")[1];
                if (users.stream().anyMatch(u -> u.username.equals(username))) {
                    sendServerMessage(MessageType.INFO, "Username already exists, please try again.");
                    return;
                }
                this.user = new User(username, password);
                clients.add(this);
                users.add(this.user);
                // Create a message storage for the new user
                clientMessages.putIfAbsent(user.username, new LinkedList<>());
                System.out.println(
                        "Successfully registered user: " + user.username);
            } else {
                sendServerMessage(MessageType.ERROR, "Invalid command. Exiting...");
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
            // If successful login or registration, send <username:inboxcount>
            sendServerMessage(MessageType.SUCCESS, user.username + ":" + clientMessages.get(user.username).size());
        } catch (Exception e) { // User disconnected
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    /**
     * Sends a message from the current user to the specified receiver.
     * If the receiver is not found, an error message is sent.
     * The message is added to the receiver's message list.
     * If the message contains a read receipt, the method returns without sending a
     * "MESSAGE SENT" notification.
     *
     * @param receiver The username of the message receiver.
     * @param message  The content of the message.
     */
    public void sendClientMessage(String receiver, String message) {
        // If the receiver is not found, send an error message
        if (clientMessages.get(receiver) == null) {
            sendServerMessage(MessageType.INFO, "MESSAGE FAILED! User not found.");
            return;
        }
        clientMessages.get(receiver).add(user.username + ": " + message);
        if (message.contains("has read your message")) // Don't send MESSAGE SENT on read reciepts
            return;
        sendServerMessage(MessageType.INFO, "MESSAGE SENT");
    }

    /**
     * Sends a server message to the client.
     *
     * @param msgCode the message type code
     * @param message the message to be sent
     */
    public void sendServerMessage(MessageType msgCode, String message) {
        try {
            String ciphertext = AESUtil.encrypt(msgCode.prefix + message, secretKey);
            bufferedWriter.write(ciphertext);
            bufferedWriter.newLine();
            bufferedWriter.flush();
        } catch (IOException e) {
            System.out.println("An error occured encrypting on the server");
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    /**
     * Reads an encrypted message from the client and decrypts it using the secret
     * key.
     * 
     * @return the decrypted message as a String, or null if an error occurs
     */
    public String readEncryptedMessage() {
        try {
            return AESUtil.decrypt(bufferedReader.readLine(), secretKey);
        } catch (IOException e) {
            sendServerMessage(MessageType.ERROR, "MESSAGE FAILED! An error occured on the server.");
            return null;
        }
    }

    /**
     * Reads all the messages stored for the current client.
     * If there are no messages in storage, it sends a read error message to the
     * server.
     * Otherwise, it sends the stored messages to the server and sends a read
     * receipt to the message senders.
     */
    public void readAllClientMessages() {
        // If no messages in storage, send a read error
        if (clientMessages.get(user.username).isEmpty()) {
            sendServerMessage(MessageType.INFO, "READ ERROR! No messages to read.");
            return;
        }
        StringBuilder messages = new StringBuilder();
        // Send stored messages until the queue is empty
        while (!clientMessages.get(user.username).isEmpty()) {
            String message = clientMessages.get(user.username).poll();
            // if message is the tailing message, don't append a newline
            messages.append(clientMessages.get(user.username).peek() == null ? message : message + "\n");
            String sender = message.split(":")[0];

            // Send read reciept if the sender is not the user, and the message itself is
            // not a read reciept
            if (!sender.equals(user.username) && !message.contains("has read your message"))
                sendClientMessage(sender, "has read your message at " + new Timestamp(System.currentTimeMillis()));
        }
        sendServerMessage(MessageType.SUCCESS, messages.toString());
    }

    /**
     * Removes the client from the list of active clients, logs out the user if
     * logged in,
     * and closes the socket, BufferedReader, and BufferedWriter.
     *
     * @param socket         the Socket object representing the client's connection
     * @param bufferedReader the BufferedReader object used for reading input from
     *                       the client
     * @param bufferedWriter the BufferedWriter object used for writing output to
     *                       the client
     */
    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
        clients.remove(this);
        // find user in users by username, and log them out
        if (user != null) {
            users.stream().filter(u -> u.username.equals(user.username)).findFirst().ifPresent(u -> u.logout());
        }
        System.out.println(user.username + " disconnected!");
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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Executes the main logic for handling a client connection.
     * This method establishes a shared secret with the client using Diffie-Hellman
     * key exchange,
     * handles client authentication, and processes valid commands received from the
     * client.
     * The method continues to handle commands until the client disconnects or an
     * error occurs.
     */
    @Override
    public void run() {

        // Establish shared secret with client
        DiffieHellmanKeyExchange();

        // Handle client authentication
        handleAuthentication();

        String commandFromClient;

        // Handle only valid commands from the client
        while (socket.isConnected()) {
            try {
                commandFromClient = readEncryptedMessage();
                if (commandFromClient.equals("EXIT")) {
                    closeEverything(socket, bufferedReader, bufferedWriter);
                    break;
                }
                if (commandFromClient.equals("READ")) {
                    readAllClientMessages();
                }
                if (commandFromClient.matches("^COMPOSE\\s\\S+$")) {
                    String receiver = commandFromClient.substring(8);
                    String message = readEncryptedMessage();
                    sendClientMessage(receiver, message);
                }

            } catch (Exception e) {
                sendServerMessage(MessageType.ERROR, "Something went wrong for the server. Exiting...");
                closeEverything(socket, bufferedReader, bufferedWriter);
                break; // exit the loop - client disconnected
            }
        }
    }

}