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
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.*;

public class SecureFileServer {
    private static final int SERVER_PORT = 8443;
    private static final String KEYSTORE_PATH = "server.keystore";
    private static final String KEYSTORE_PASSWORD = "Diego241202";
    private static final String FILE_STORAGE_PATH = "C:\\Users\\guinc\\Desktop\\stuff\\ServerStorage"; // Directory for storing user folders

    private static final String DB_URL = "jdbc:mysql://localhost:3306/secure_file_storage";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "-------"; // replace with password 

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
            InputStream inStream = clientSocket.getInputStream();
            OutputStream outStream = clientSocket.getOutputStream();
            DataInputStream in = new DataInputStream(inStream);
            DataOutputStream out = new DataOutputStream(outStream);
        ) {
            out.writeUTF("Welcome to the Server");
            out.writeUTF("Available commands: LOGIN <username> <password>, REGISTER <username> <password>, LIST, UPLOAD <filename>, DOWNLOAD <filename>, DELETE <filename>, EXIT");

            String clientMessage;
            while (true) {
                clientMessage = in.readUTF();
                logger.info("Received command from client: " + clientMessage);
                String[] tokens = clientMessage.split(" ", 3); // Allow up to 3 tokens
                String command = tokens[0].toUpperCase();

                switch (command) {
                    case "LOGIN":
                        if (tokens.length < 3) {
                            out.writeUTF("Error: Username or password not specified.");
                        } else {
                            String username = tokens[1];
                            String password = tokens[2];
                            boolean isValid = validateUser(username, password);
                            if (isValid) {
                                currentUser = username;
                                createUserFolder(currentUser);
                                out.writeUTF("Login successful.");
                            } else {
                                out.writeUTF("Error: Invalid username or password.");
                            }
                        }
                        break;
                    case "REGISTER":
                        if (tokens.length < 3) {
                            out.writeUTF("Error: Username or password not specified.");
                        } else {
                            String username = tokens[1];
                            String password = tokens[2];
                            boolean isRegistered = registerUser(username, password);
                            if (isRegistered) {
                                out.writeUTF("Registration successful. You can now login.");
                            } else {
                                out.writeUTF("Error: Registration failed. User may already exist.");
                            }
                        }
                        break;
                    case "LIST":
                        if (isLoggedIn(currentUser, out)) {
                            handleListCommand(out, currentUser);
                        }
                        break;
                    case "UPLOAD":
                        if (isLoggedIn(currentUser, out)) {
                            if (tokens.length < 2) {
                                out.writeUTF("Error: Filename not specified.");
                            } else {
                                handleUploadCommand(in, out, tokens[1], currentUser);
                            }
                        }
                        break;
                    case "DOWNLOAD":
                        if (isLoggedIn(currentUser, out)) {
                            if (tokens.length < 2) {
                                out.writeUTF("Error: Filename not specified.");
                            } else {
                                handleDownloadCommand(in, out, tokens[1], currentUser);
                            }
                        }
                        break;
                    case "DELETE":
                        if (isLoggedIn(currentUser, out)) {
                            if (tokens.length < 2) {
                                out.writeUTF("Error: Filename not specified.");
                            } else {
                                handleDeleteCommand(out, tokens[1], currentUser);
                            }
                        }
                        break;
                    case "EXIT":
                        out.writeUTF("Goodbye!");
                        clientSocket.close();
                        return;
                    default:
                        out.writeUTF("Unknown command.");
                        break;
                }
            }
        } catch (EOFException e) {
            logger.info("Client disconnected.");
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
        String query = "SELECT password_hash FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement(query)) {

            stmt.setString(1, username);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    String storedPassword = rs.getString("password_hash");
                    return storedPassword.equals(password);
                }
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database connection error: ", e);
        }
        return false;
    }

    private static boolean registerUser(String username, String password) {
        String query = "INSERT INTO users (username, password_hash) VALUES (?, ?)";
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement(query)) {


            // generate symmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            byte[] symmetricKey = secretKey.getEncoded();

            stmt.setString(1, username);
            stmt.setString(2, password); // Store the password as-is
            stmt.setBytes(3, symmetricKey); // Store the symmetric key

            int rowsAffected = stmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            if (e.getSQLState().equals("23000")) { // Duplicate entry
                logger.log(Level.INFO, "User already exists: " + username);
            } else {
                logger.log(Level.SEVERE, "Database error during registration: ", e);
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error generating symmetric key: ", e);
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

    private static boolean isLoggedIn(String currentUser, DataOutputStream out) throws IOException {
        if (currentUser == null) {
            out.writeUTF("Error: You must be logged in to perform this action.");
            return false;
        }
        return true;
    }

    private static void handleListCommand(DataOutputStream out, String currentUser) throws IOException {
        File userFolder = new File(FILE_STORAGE_PATH, currentUser);
        File[] listOfFiles = userFolder.listFiles();

        if (listOfFiles != null && listOfFiles.length > 0) {
            out.writeUTF("Your files:");
            for (File file : listOfFiles) {
                if (file.isFile()) {
                    out.writeUTF(file.getName());
                }
            }
            out.writeUTF("END_OF_LIST");
        } else {
            out.writeUTF("No files found in your folder.");
        }
    }

    private static void handleUploadCommand(DataInputStream in, DataOutputStream out, String fileName, String currentUser) throws IOException {
        out.writeUTF("Ready to receive file size.");

        // Receive file size
        long fileSize = in.readLong();
        Path filePath = Paths.get(FILE_STORAGE_PATH, currentUser, fileName);

        // Receive file data
        try (OutputStream fileOut = Files.newOutputStream(filePath)) {
            byte[] buffer = new byte[4096];
            long totalBytesRead = 0;
            int bytesRead;

            while (totalBytesRead < fileSize && (bytesRead = in.read(buffer, 0, (int)Math.min(buffer.length, fileSize - totalBytesRead))) != -1) {
                fileOut.write(buffer, 0, bytesRead);
                totalBytesRead += bytesRead;
            }
        }

        out.writeUTF("File uploaded successfully.");
    }

    private static void handleDownloadCommand(DataInputStream in, DataOutputStream out, String fileName, String currentUser) throws IOException {
        Path filePath = Paths.get(FILE_STORAGE_PATH, currentUser, fileName);
        if (Files.exists(filePath)) {
            long fileSize = Files.size(filePath);
            out.writeUTF("READY");
            out.writeLong(fileSize);

            try (InputStream fileIn = Files.newInputStream(filePath)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fileIn.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            out.flush();
        } else {
            out.writeUTF("Error: File not found.");
        }
    }

    private static void handleDeleteCommand(DataOutputStream out, String fileName, String currentUser) throws IOException {
        Path filePath = Paths.get(FILE_STORAGE_PATH, currentUser, fileName);
        if (Files.exists(filePath)) {
            try {
                Files.delete(filePath);
                out.writeUTF("File deleted successfully.");
            } catch (IOException e) {
                out.writeUTF("Error deleting file.");
                logger.log(Level.WARNING, "Error deleting file: " + fileName, e);
            }
        } else {
            out.writeUTF("Error: File not found.");
        }
    }
}