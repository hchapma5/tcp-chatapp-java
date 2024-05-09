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
                /* Create a message storage for the new user */
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

    public String readEncryptedMessage() {
        try {
            return AESUtil.decrypt(bufferedReader.readLine(), secretKey);
        } catch (IOException e) {
            sendServerMessage(MessageType.ERROR, "MESSAGE FAILED! An error occured on the server.");
            return null;
        }
    }

    public void readAllClientMessages() {
        // If no messages in storage, send a read error
        if (clientMessages.get(user.username).isEmpty()) {
            sendServerMessage(MessageType.INFO, "READ ERROR! No messages to read.");
        }
        // Send stored messages until the queue is empty
        while (!clientMessages.get(user.username).isEmpty()) {
            String message = clientMessages.get(user.username).poll();
            String sender = message.split(":")[0];
            sendServerMessage(MessageType.SUCCESS, message);

            // Send read reciept if the sender is not the user, and the message itself is
            // not a read reciept
            if (!sender.equals(user.username) && !message.contains("has read your message"))
                sendClientMessage(sender, "has read your message at " + new Timestamp(System.currentTimeMillis()));
        }
    }

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