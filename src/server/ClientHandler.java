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
    private SecretKey secretKey;

    public ClientHandler(Socket socket) {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            DHkeyExchange();
            handleClientLogin();
        } catch (IOException e) {
            System.out.println("Error creating client handler: " + e.getMessage());
            closeEverything(socket, bufferedReader, bufferedWriter);
        }

    }

    public void DHkeyExchange() {
        try {
            KeyPair keyPair = AESUtil.generateDHKeyPair();
            // Receive public key from client
            byte[] clientPublicKey = Base64.getDecoder().decode(bufferedReader.readLine());
            // Send public key to client
            bufferedWriter.write(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            bufferedWriter.newLine();
            bufferedWriter.flush();
            // Generate shared secret
            byte[] sharedSecret = AESUtil.generateSharedSecret(keyPair.getPrivate(), clientPublicKey);
            secretKey = AESUtil.deriveAESKey(sharedSecret);
        } catch (Exception e) {
            sendServerMessage("Failed to establish shared secret with client");
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void handleClientLogin() {
        try {
            String command = bufferedReader.readLine();
            // if command matches "LOGIN <username>:<password>
            if (command != null && command.matches("^LOGIN\\s\\S+:\\S+$")) {
                String username = command.substring(6).split(":")[0];
                String password = command.substring(6).split(":")[1];
                clients.add(this); // add this connection
                // Find user in users by username
                user = users.stream().filter(u -> u.username.equals(username)).findFirst().orElse(null);
                // If user not found, send invalid login message
                if (user == null) {
                    sendServerMessage("Invalid username, please try again.");
                    closeEverything(socket, bufferedReader, bufferedWriter);
                    return;
                }
                if (!user.checkPassword(password)) {
                    sendServerMessage("Invalid password, please try again.");
                    closeEverything(socket, bufferedReader, bufferedWriter);
                    return;
                }
                // User should be logged in!
                /* Return the amount of messages stored for the client */
                String clientInboxCount = Integer.toString(clientMessages.get(user.username).size());
                bufferedWriter.write(clientInboxCount);
                bufferedWriter.newLine();
                bufferedWriter.flush();
                // else if command matches "REGISTER <username>:<password>"
            } else if (command != null && command.matches("^REGISTER\\s\\S+:\\S+$")) {
                String username = command.substring(9).split(":")[0];
                String password = command.substring(9).split(":")[1];
                clients.add(this);
                user = new User(username, password);
                users.add(user);
                /* If client hasn't logged in before, create message storage */
                clientMessages.putIfAbsent(user.username, new LinkedList<>());
                /* Return the amount of messages stored for the client */
                String clientInboxCount = Integer.toString(clientMessages.get(user.username).size());
                bufferedWriter.write(clientInboxCount);
                bufferedWriter.newLine();
                bufferedWriter.flush();
            } else {
                sendServerMessage("INVALID LOGIN COMMAND");
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        } catch (Exception e) {
            sendServerMessage("Something went wrong with the server: Exiting...");
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void sendClientMessage(String receiver, String message) {
        try {
            /* If the receiver hasn't logged in before, create entry in message bank */
            if (clientMessages.get(receiver) == null)
                clientMessages.put(receiver, new LinkedList<>());

            clientMessages.get(receiver).add(clientUsername + ": " + message);
            sendServerMessage("MESSAGE SENT");
            return;
        } catch (Exception e) {
            sendServerMessage("MESSAGE FAILED");
        }
    }

    public void sendServerMessage(String message) {
        try {
            bufferedWriter.write("Server: " + message);
            bufferedWriter.newLine();
            bufferedWriter.flush();
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void readAllClientMessages() {
        /* If no messages in storage, send a read error */
        if (clientMessages.get(clientUsername).isEmpty()) {
            sendServerMessage("READ ERROR");
            return;
        }
        /* Send stored messages until the queue is empty */
        while (!clientMessages.get(clientUsername).isEmpty()) {
            try {
                bufferedWriter.write(clientMessages.get(clientUsername).poll());
                bufferedWriter.newLine();
                bufferedWriter.flush();
            } catch (IOException e) {
                sendServerMessage("Something went wrong with the server. Exiting...");
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
                sendServerMessage("Something went wrong for the server. Exiting...");
                closeEverything(socket, bufferedReader, bufferedWriter);
                break; // exit the loop - client disconnected
            }
        }
    }

}