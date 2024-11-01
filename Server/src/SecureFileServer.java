// SecureFileServer.java
import java.io.*;
import java.nio.file.*;
import java.security.KeyStore;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.*;

public class SecureFileServer {
    private static final int SERVER_PORT = 8443;
    private static final String KEYSTORE_PATH = "server.keystore";
    private static final String KEYSTORE_PASSWORD = "Diego241202"; 
    private static final String FILE_STORAGE_PATH = "C:\\Users\\guinc\\Desktop\\stuff\\ServerStorage"; // Directory for storing user folders

    private static final String DB_URL = "jdbc:mysql://localhost:3306/your_database"; // Update with actual database URL
    private static final String DB_USER = "dbUsername"; // Database user
    private static final String DB_PASSWORD = "dbPassword"; // Database password

    private static final Logger logger = Logger.getLogger(SecureFileServer.class.getName());

    public static void main(String[] args) {
        SSLServerSocket serverSocket = null;
        try {
            // Load SSL context with the server's keystore
            SSLContext sslContext = SSLContext.getInstance("TLS");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore ks = KeyStore.getInstance("JKS");

            // Load the server's keystore
            char[] passphrase = KEYSTORE_PASSWORD.toCharArray();
            ks.load(new FileInputStream(KEYSTORE_PATH), passphrase);
            kmf.init(ks, passphrase);
            sslContext.init(kmf.getKeyManagers(), null, null);

            // Create SSLServerSocketFactory and SSLServerSocket
            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
            serverSocket = (SSLServerSocket) ssf.createServerSocket(SERVER_PORT);
            logger.info("Server started and listening on port " + SERVER_PORT);

            // Ensure the file storage directory exists
            Path storagePath = Paths.get(FILE_STORAGE_PATH);
            if (!Files.exists(storagePath)) {
                Files.createDirectories(storagePath);
            }

            // Continuously accept client connections
            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                logger.info("New client connected: " + clientSocket.getInetAddress());

                // Handle client connection in a new thread
                new Thread(() -> handleClient(clientSocket)).start();
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Server encountered an error: ", e);
        } finally {
            // Ensure the server socket is closed when the application shuts down
            if (serverSocket != null && !serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                    logger.log(Level.WARNING, "Error closing server socket: ", e);
                }
            }
        }
    }

    private static void handleClient(SSLSocket clientSocket) {
        String currentUser = null; // Track the logged-in user
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
        ) {
            out.write("Welcome to the Secure Server!\n");
            out.write("Available commands: LOGIN <username> <password>, LIST, UPLOAD <filename>, DOWNLOAD <filename>, DELETE <filename>, EXIT\n");
            out.flush();

            String clientMessage;
            while ((clientMessage = in.readLine()) != null) {
                logger.info("Received command from client: " + clientMessage);
                String[] tokens = clientMessage.split(" ", 3); // Allow up to 3 tokens
                String command = tokens[0].toUpperCase();

                switch (command) {
                    case "LOGIN":
                        if (tokens.length < 3) {
                            out.write("Error: Username or password not specified.\n");
                        } else {
                            String username = tokens[1];
                            String password = tokens[2];
                            boolean isValid = validateUser(username, password);
                            if (isValid) {
                                currentUser = username;
                                createUserFolder(currentUser);
                                out.write("Login successful.\n");
                            } else {
                                out.write("Error: Invalid username or password.\n");
                            }
                        }
                        out.flush();
                        break;
                    case "LIST":
                        if (isLoggedIn(currentUser, out)) {
                            handleListCommand(out, currentUser);
                        }
                        break;
                    case "UPLOAD":
                        if (isLoggedIn(currentUser, out)) {
                            if (tokens.length < 2) {
                                out.write("Error: Filename not specified.\n");
                            } else {
                                handleUploadCommand(in, out, tokens[1], currentUser);
                            }
                            out.flush();
                        }
                        break;
                    case "DOWNLOAD":
                        if (isLoggedIn(currentUser, out)) {
                            if (tokens.length < 2) {
                                out.write("Error: Filename not specified.\n");
                            } else {
                                handleDownloadCommand(out, tokens[1], currentUser);
                            }
                            out.flush();
                        }
                        break;
                    case "DELETE":
                        if (isLoggedIn(currentUser, out)) {
                            if (tokens.length < 2) {
                                out.write("Error: Filename not specified.\n");
                            } else {
                                handleDeleteCommand(out, tokens[1], currentUser);
                            }
                            out.flush();
                        }
                        break;
                    case "EXIT":
                        out.write("Goodbye!\n");
                        out.flush();
                        clientSocket.close();
                        return;
                    default:
                        out.write("Unknown command.\n");
                        out.flush();
                        break;
                }
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "Client connection error: ", e);
        } finally {
            try {
                if (clientSocket != null && !clientSocket.isClosed()) {
                    clientSocket.close();
                }
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error closing client socket: ", e);
            }
        }
    }

    private static boolean validateUser(String username, String password) {
        String query = "SELECT 1 FROM users WHERE username = ? AND password = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement(query)) {
                 
            stmt.setString(1, username);
            stmt.setString(2, password);

            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database connection error: ", e);
        }
        return false;
    }

    private static void createUserFolder(String username) {
        Path userFolderPath = Paths.get(FILE_STORAGE_PATH, username);
        if (!Files.exists(userFolderPath)) {
            try {
                Files.createDirectories(userFolderPath);
                logger.info("Created directory for user: " + username);
            } catch (IOException e) {
                logger.log(Level.SEVERE, "Failed to create directory for user: " + username, e);
            }
        }
    }

    private static boolean isLoggedIn(String currentUser, BufferedWriter out) throws IOException {
        if (currentUser == null) {
            out.write("Error: You must be logged in to perform this action.\n");
            out.flush();
            return false;
        }
        return true;
    }

    private static void handleListCommand(BufferedWriter out, String currentUser) throws IOException {
        File userFolder = new File(FILE_STORAGE_PATH, currentUser);
        File[] listOfFiles = userFolder.listFiles();

        if (listOfFiles != null && listOfFiles.length > 0) {
            out.write("Your files:\n");
            for (File file : listOfFiles) {
                if (file.isFile()) {
                    out.write(file.getName() + "\n");
                }
            }
        } else {
            out.write("No files found in your folder.\n");
        }
        out.flush();
    }

    private static void handleUploadCommand(BufferedReader in, BufferedWriter out, String fileName, String currentUser) throws IOException {
        out.write("Ready to receive file content. End with a single line 'EOF'.\n");
        out.flush();

        StringBuilder fileContent = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null && !line.equals("EOF")) {
            fileContent.append(line).append(System.lineSeparator());
        }

        Path filePath = Paths.get(FILE_STORAGE_PATH, currentUser, fileName);
        Files.write(filePath, fileContent.toString().getBytes());

        out.write("File uploaded successfully.\n");
        out.flush();
    }

    private static void handleDownloadCommand(BufferedWriter out, String fileName, String currentUser) throws IOException {
        Path filePath = Paths.get(FILE_STORAGE_PATH, currentUser, fileName);
        if (Files.exists(filePath)) {
            out.write("File content:\n");
            Files.lines(filePath).forEach(line -> {
                try {
                    out.write(line + "\n");
                } catch (IOException e) {
                    logger.log(Level.WARNING, "Error sending file content: ", e);
                }
            });
            out.write("End of file.\n");
        } else {
            out.write("Error: File not found.\n");
        }
        out.flush();
    }

    private static void handleDeleteCommand(BufferedWriter out, String fileName, String currentUser) throws IOException {
        Path filePath = Paths.get(FILE_STORAGE_PATH, currentUser, fileName);
        if (Files.exists(filePath)) {
            try {
                Files.delete(filePath);
                out.write("File deleted successfully.\n");
            } catch (IOException e) {
                out.write("Error deleting file.\n");
                logger.log(Level.WARNING, "Error deleting file: " + fileName, e);
            }
        } else {
            out.write("Error: File not found.\n");
        }
        out.flush();
    }
}
