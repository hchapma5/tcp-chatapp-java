import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ConnectException;
import java.net.Socket;
import java.util.Scanner;

/**
 * TODO:
 * 
 * Safe guide Client:
 * 1. should prompt user to enter a username, and automatically send a LOGIN
 * message to the server
 * 2. Client should guide the user through an interaction with the server until
 * the user enters EXIT
 * 3. Client should ensure only valid commands are sent to the server.
 * 4. invalid client commands should result in notifying the user and request
 * new input.
 * 5. Add documentation for each function
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

    public void sendMessages(String login) {
        try {
            bufferedWriter.write(login); // LOGIN <username> (e.g. LOGIN Alice)
            bufferedWriter.newLine();
            bufferedWriter.flush();

            Scanner scanner = new Scanner(System.in);

            while (!socket.isClosed()) {
                String messageToSpend = scanner.nextLine();
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

                        if (messageFromChat == null)
                            closeEverything(socket, bufferedReader, bufferedWriter);

                        System.out.println(messageFromChat);
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

    public static void clientCommandHandler(String command) {
        if (command.equals("EXIT")) {
            System.exit(0);
        }

    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java Client <hostname> <port>");
            return; // exit if no port number provided
        }

        try {
            String hostname = args[0];
            int port = Integer.parseInt(args[1]);
            Scanner scanner = new Scanner(System.in);
            String login = scanner.nextLine();
            if (login.equals("EXIT"))
                System.exit(0);

            /* If invalid, Prompt login until valid */
            while (!login.matches("^LOGIN\\s\\S+$")) {
                if (login.equals("EXIT"))
                    System.exit(0);

                System.out.print("Invalid command, use: LOGIN <username>\n");
                login = scanner.nextLine();
            }

            Socket socket = new Socket(hostname, port);
            Client client = new Client(socket);
            client.listenForMessage();
            client.sendMessages(login);

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