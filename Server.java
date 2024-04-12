import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

class Server {

    private ServerSocket serverSocket;

    public Server(ServerSocket serverSocket) {
        this.serverSocket = serverSocket;
    }

    public void start() {
        try {

            while (!serverSocket.isClosed()) {

                Socket socket = serverSocket.accept(); // blocking
                System.out.println("A new client has connected!");
                ClientHandler clientHandler = new ClientHandler(socket);

                Thread thread = new Thread(clientHandler);
                thread.start();

            }

        } catch (Exception e) {

            e.printStackTrace();
        }
    }

    public void closeServerSocket() {
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException {

        if (args.length < 1) {
            System.out.println("Usage: java Server <port>");
            return; // exit if no port number provided
        }

        try {
            int port = Integer.parseInt(args[0]);
            ServerSocket serverSocket = new ServerSocket(port);
            Server server = new Server(serverSocket);
            server.start();
        } catch (NumberFormatException e) {
            System.out.println("Invalid port number");
            return; // exit if invalid port number
        }

    }

}