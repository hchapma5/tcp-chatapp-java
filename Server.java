import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * The Server class represents a TCP chat server that listens for incoming
 * client connections
 * and handles them using separate threads.
 */
class Server {

    private ServerSocket serverSocket;

    public Server(ServerSocket serverSocket) {
        this.serverSocket = serverSocket;
    }

    public void start() {
        try {
            while (!serverSocket.isClosed()) {
                Socket socket = serverSocket.accept();
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
            if (serverSocket != null)
                serverSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
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
            System.out.println("Invalid port number. Please try again.");
            return;
        } catch (IOException e) {
            System.out.println("Failed to create server socket on port " + args[0] + ". Please try again.");
        }

    }

}