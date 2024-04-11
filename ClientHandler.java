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
    public static Queue<String> messages = new LinkedList<>();

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
            if (command.matches("^LOGIN\\s\\S+$")) {
                clientUsername = command.substring(6);
                clientHandlers.put(clientUsername, this);
                sendServerMessage(Integer.toString(messages.size()));
            } else {
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void sendClientMessage(String receiver, String message) {
        try {
            if (!clientHandlers.containsKey(receiver)) {

            }

            ClientHandler receiverClient = clientHandlers.get(receiver);
            receiverClient.bufferedWriter.write(clientUsername + ": " + message);
            receiverClient.bufferedWriter.newLine();
            receiverClient.bufferedWriter.flush();
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
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

                switch (commandFromClient) {

                    case "EXIT" -> {
                        closeEverything(socket, bufferedReader, bufferedWriter);
                        break;
                    }

                    case "READ" -> {
                        while (!messages.isEmpty()) {
                            bufferedWriter.write(messages.poll());
                            bufferedWriter.newLine();
                            bufferedWriter.flush();
                        }
                    }

                    default -> {
                        if (commandFromClient.matches("^COMPOSE\\s\\S+$")) {

                            String receiver = commandFromClient.substring(8);
                            String message = bufferedReader.readLine();

                            if (receiver.equals(clientUsername)) {
                                sendServerMessage("MESSAGE FAILED");
                                break;
                            }

                            sendClientMessage(receiver, message);
                        }
                    }
                }

            } catch (IOException e) {
                closeEverything(socket, bufferedReader, bufferedWriter);
                break; // exit the loop - client disconnected
            }
        }
    }

}
