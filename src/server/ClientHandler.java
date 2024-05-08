package src.server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Queue;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
        } catch (Exception e) {
            // TODO: look into this
            e.printStackTrace();
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
                if (clients.stream().anyMatch(c -> c.user.username.equals(username))) {
                    sendServerMessage(MessageType.INFO, "User already logged in, please try again.");
                    return;
                }
            } else if (command != null && command.matches("^REGISTER\\s\\S+:\\S+$")) {
                String username = command.substring(9).split(":")[0];
                String password = command.substring(9).split(":")[1];
                System.out.println("Registering user: " + username + " with password: " + password);
                if (users.stream().anyMatch(u -> u.username.equals(username))) {
                    sendServerMessage(MessageType.INFO, "Username already exists, please try again.");
                    return;
                }
                this.user = new User(username, password);
                System.out.println(
                        "Successfully created User: " + user.username);
                users.add(user);
                clients.add(this);
                /* Create a message storage for the new user */
                clientMessages.putIfAbsent(user.username, new LinkedList<>());
            } else {
                sendServerMessage(MessageType.ERROR, "Invalid command. Exiting...");
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
            // If successful login or registration, send <username:inboxcount>
            sendServerMessage(MessageType.SUCCESS, user.username + ":" + clientMessages.get(user.username).size());
        } catch (Exception e) {
            // TODO: look into this
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public String readEncryptedMessage() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, IOException {
        return AESUtil.decrypt(bufferedReader.readLine(), secretKey);
    }

    public void sendClientMessage(String receiver, String message)
            throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, IOException {
        try {
            /* If the receiver hasn't logged in before, create entry in message bank */
            if (clientMessages.get(receiver) == null)
                clientMessages.put(receiver, new LinkedList<>());

            clientMessages.get(receiver).add(user.username + ": " + message);
            sendServerMessage(MessageType.SUCCESS, "MESSAGE SENT");
            return;
        } catch (Exception e) {
            sendServerMessage(MessageType.INFO, "MESSAGE FAILED");
        }
    }

    public void sendServerMessage(MessageType msgCode, String message) {
        String ciphertext = AESUtil.encrypt(message, secretKey);
        try {
            bufferedWriter.write(msgCode + ciphertext);
            bufferedWriter.newLine();
            bufferedWriter.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void readAllClientMessages() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, IOException {
        /* If no messages in storage, send a read error */
        if (clientMessages.get(user.username).isEmpty()) {
            sendServerMessage(MessageType.INFO, "READ ERROR");
            return;
        }
        /* Send stored messages until the queue is empty */
        while (!clientMessages.get(user.username).isEmpty()) {
            sendServerMessage(MessageType.SUCCESS, clientMessages.get(user.username).poll());
        }
    }

    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
        clients.remove(this);
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