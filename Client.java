import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ConnectException;
import java.net.Socket;
import java.util.Scanner;

/**
 * The Client class represents a client in a TCP chat application.
 * It is responsible for establishing a connection with the server,
 * sending and receiving messages, and handling user commands.
 */
public class Client {

    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;

    public Client(Socket socket) {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (Exception e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void displayCommandProtocols() {
        System.out.println("Command Protocols: \n");
        System.out.println("COMPOSE <username> - Send a message to <username>");
        System.out.println("READ - Read messages from the server");
        System.out.println("EXIT - disconnect from server\n");
    }

    public void sendLoginCommand(String username) {
        try {
            bufferedWriter.write("LOGIN " + username);
            bufferedWriter.newLine();
            bufferedWriter.flush();
            displayCommandProtocols();
        } catch (Exception e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void sendMessages() {
        try (Scanner scanner = new Scanner(System.in)) {

            // Store previous command to handle COMPOSE messages
            String previousMessage = " ";

            while (!socket.isClosed()) {
                String messageToSpend = scanner.nextLine();
                // handle invalid commands
                while (!isValidCommand(messageToSpend) && !previousMessage.matches("^COMPOSE\\s\\S+$")) {
                    System.out.println("Invalid command. Try again.");
                    messageToSpend = scanner.nextLine();
                }
                previousMessage = messageToSpend;
                bufferedWriter.write(messageToSpend);
                bufferedWriter.newLine();
                bufferedWriter.flush();
            }
        } catch (Exception e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void listenForMessage() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String messageFromChat;
                while (socket.isConnected()) {
                    try {
                        messageFromChat = bufferedReader.readLine();
                        // If server sends null, close everything (EXIT command)
                        if (messageFromChat == null)
                            closeEverything(socket, bufferedReader, bufferedWriter);
                        // Read messages from server
                        System.out.println(messageFromChat);
                    } catch (Exception e) {
                        closeEverything(socket, bufferedReader, bufferedWriter);
                    }
                }
            }
        }).start();
    }

    public static boolean isValidCommand(String command) {
        if (command.equals("EXIT"))
            return true;
        if (command.equals("READ"))
            return true;
        if (command.matches("^COMPOSE\\s\\S+$"))
            return true;
        return false;
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

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java Client <hostname> <port>");
            return; // exit if no port number provided
        }
        String hostname = args[0];
        int port = Integer.parseInt(args[1]);
        try (Scanner scanner = new Scanner(System.in)) {

            // Handle client login
            System.out.print("Enter username: ");
            String username = scanner.nextLine();

            // Prompt client for valid username
            while (!username.matches("^[^\\s]+$")) {
                // Exit if user types EXIT before logging in
                if (username.equals("EXIT"))
                    System.exit(0);
                System.out.println("Invalid username: Try again with no spaces.");
                username = scanner.nextLine();
            }

            // Connect to server
            Socket socket = new Socket(hostname, port);
            Client client = new Client(socket);
            client.sendLoginCommand(username);

            // Send & Receive messages
            client.listenForMessage();
            client.sendMessages();

        } catch (NumberFormatException e) {
            System.out.println("Invalid port number");
            return; // exit if invalid port number
        } catch (ConnectException e) {
            System.out.println("Connection refused. Server may be down.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}