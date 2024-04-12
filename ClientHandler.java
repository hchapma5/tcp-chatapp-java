import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Queue;

public class ClientHandler implements Runnable {

    public static HashMap<String, ClientHandler> clientHandlers = new HashMap<>();
    public static HashMap<String, Queue<String>> clientMessages = new HashMap<>();

    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private String clientUsername;

    public ClientHandler(Socket socket) {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            handleClientLogin();
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }

    }

    public void handleClientLogin() {
        try {
            String command = bufferedReader.readLine();
            if (command != null && command.matches("^LOGIN\\s\\S+$")) {
                clientUsername = command.substring(6);
                clientHandlers.put(clientUsername, this);
                /* If client hasn't logged in before, create message storage */
                clientMessages.putIfAbsent(clientUsername, new LinkedList<>());
                /* Return the amount of messages stored for the client */
                sendServerMessage(Integer.toString(clientMessages.get(clientUsername).size()));
            } else {
                sendServerMessage("INVALID LOGIN COMMAND");
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void sendClientMessage(String receiver, String message) {
        try {
            /* client not online, store message in message bank */
            if (!clientHandlers.containsKey(receiver)) {
                /* If the user hasn't logged in before, create entry in message bank */
                if (clientMessages.get(receiver) == null)
                    clientMessages.put(receiver, new LinkedList<>());

                clientMessages.get(receiver).add(clientUsername + ": " + message);
                sendServerMessage("MESSAGE SENT");
                return;

            }
            ClientHandler receiverClient = clientHandlers.get(receiver);
            receiverClient.bufferedWriter.write(clientUsername + ": " + message);
            receiverClient.bufferedWriter.newLine();
            receiverClient.bufferedWriter.flush();
            sendServerMessage("MESSAGE SENT");
        } catch (IOException e) {
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
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        }
    }

    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
        clientHandlers.remove(clientUsername);
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

        while (socket.isConnected()) {
            try {
                commandFromClient = bufferedReader.readLine(); // blocking

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

                // If invalid username (e.g. COMPOSE first last)
                if (commandFromClient.startsWith("COMPOSE") && !commandFromClient.matches("^COMPOSE\\s\\S+$"))
                    sendServerMessage("MESSAGE FAILED");

            } catch (IOException e) {
                closeEverything(socket, bufferedReader, bufferedWriter);
                break; // exit the loop - client disconnected
            }
        }
    }

}