import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Scanner;

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

                if (messageToSpend.equals("EXIT")) {
                    closeEverything(socket, bufferedReader, bufferedWriter);
                }

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

    public static void main(String[] args) throws UnknownHostException, IOException {
        if (args.length < 1) {
            System.out.println("Usage: java Client <port>");
            return; // exit if no port number provided
        }

        try {
            int port = Integer.parseInt(args[0]);
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

            Socket socket = new Socket("localhost", port);
            Client client = new Client(socket);
            client.listenForMessage();
            client.sendMessages(login);

        } catch (NumberFormatException e) {
            System.out.println("Invalid port number");
            return; // exit if invalid port number
        }
    }

}