package src.server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Queue;

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
    // private SecretKey secretKey;

    public ClientHandler(Socket socket) {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            // DHkeyExchange();
            while (user == null) {
                handleAuthentication();
            }
        } catch (IOException e) {
            System.out.println("Error creating client handler: " + e.getMessage());
            closeEverything(socket, bufferedReader, bufferedWriter);
        }

    }

    // public void DHkeyExchange() {
    // try {
    // KeyPair keyPair = AESUtil.generateDHKeyPair();
    // // Receive public key from client
    // byte[] clientPublicKey =
    // Base64.getDecoder().decode(bufferedReader.readLine());
    // // Send public key to client
    // bufferedWriter.write(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    // bufferedWriter.newLine();
    // bufferedWriter.flush();
    // // Generate shared secret
    // byte[] sharedSecret = AESUtil.generateSharedSecret(keyPair.getPrivate(),
    // clientPublicKey);
    // secretKey = AESUtil.deriveAESKey(sharedSecret);
    // } catch (Exception e) {
    // sendServerMessage("Failed to establish shared secret with client");
    // closeEverything(socket, bufferedReader, bufferedWriter);
    // }
    // }

    public void handleAuthentication() {
        try {
            String command = bufferedReader.readLine();
            if (command != null && command.matches("^LOGIN\\s\\S+:\\S+$")) {
                String username = command.substring(6).split(":")[0];
                String password = command.substring(6).split(":")[1];
                clients.add(this); // add this connection
                // Find user in users by username
                user = users.stream().filter(u -> u.username.equals(username)).findFirst().orElse(null);
                // If user not found, send invalid login message
                if (user == null) {
                    sendServerMessage(MessageType.INFO, "Invalid username, please try again.");
                    return;
                }
                if (!user.checkPassword(password)) {
                    sendServerMessage(MessageType.INFO, "Invalid password, please try again.");
                    return;
                }
                // User should be authenticated at this point
            } else if (command != null && command.matches("^REGISTER\\s\\S+:\\S+$")) {
                String username = command.substring(9).split(":")[0];
                String password = command.substring(9).split(":")[1];
                System.out.println("Registering user: " + username + " with password: " + password);
                if (users.stream().anyMatch(u -> u.username.equals(username))) {
                    sendServerMessage(MessageType.INFO, "Username already exists, please try again.");
                    return;
                }
                user = new User(username, password);
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
            sendServerMessage(MessageType.ERROR, "Something went wrong with the server: Exiting...");
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void sendClientMessage(String receiver, String message) {
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
        try {
            bufferedWriter.write(msgCode.prefix + message);
            bufferedWriter.newLine();
            bufferedWriter.flush();
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void readAllClientMessages() {
        /* If no messages in storage, send a read error */
        if (clientMessages.get(user.username).isEmpty()) {
            sendServerMessage(MessageType.INFO, "READ ERROR");
            return;
        }
        /* Send stored messages until the queue is empty */
        while (!clientMessages.get(user.username).isEmpty()) {
            try {
                bufferedWriter.write(clientMessages.get(user.username).poll());
                bufferedWriter.newLine();
                bufferedWriter.flush();
            } catch (IOException e) {
                sendServerMessage(MessageType.ERROR, "Something went wrong with the server. Exiting...");
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
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
        String commandFromClient;

        // Handle only valid commands from the client
        while (socket.isConnected()) {
            try {
                commandFromClient = bufferedReader.readLine();
                if (commandFromClient.equals("EXIT")) {
                    closeEverything(socket, bufferedReader, bufferedWriter);
                    break;
                }
                if (commandFromClient.equals("READ")) {
                    readAllClientMessages();
                }
                if (commandFromClient.matches("^COMPOSE\\s\\S+$")) {
                    String receiver = commandFromClient.substring(8);
                    String message = bufferedReader.readLine();
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