package src.client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ConnectException;
import java.net.Socket;
import java.net.UnknownHostException;
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

    public void spendMessage(String message) {
        try {
            bufferedWriter.write(message);
            bufferedWriter.newLine();
            bufferedWriter.flush();
        } catch (Exception e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void login(String username) throws IOException {
        spendMessage("LOGIN " + username);
        String inboxCount = bufferedReader.readLine();
        System.out.println("Welcome, " + username + "!");
        System.out.println("You have " + inboxCount + " unread messages.");
        displayCommandMenu();
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
                    spendMessage("COMPOSE " + recipient);
                    String messageToSpend = scanner.nextLine();
                    spendMessage(messageToSpend);
                }
                case "2" -> {
                    spendMessage("READ");
                }
                case "3" -> {
                    spendMessage("EXIT");
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
                        messageFromServer = bufferedReader.readLine();
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
            return; // exit if no host or port provided
        }
        try {
            String hostname = args[0];
            int port = Integer.parseInt(args[1]);

            // Connect client to server
            Socket socket = new Socket(hostname, port);
            Client client = new Client(socket);

            // Handle client login
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter username: ");
            String username = scanner.nextLine();

            // Make sure username is valid
            while (!username.matches("^[^\\s]+$")) {
                System.out.println("Invalid username: Try again with no spaces.");
                username = scanner.nextLine();
            }
            client.login(username);

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
        }
    }

}