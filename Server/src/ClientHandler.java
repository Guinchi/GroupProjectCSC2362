// ClientHandler.java
import java.io.*;
import javax.net.ssl.SSLSocket;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ClientHandler implements Runnable {
    private static final Logger logger = Logger.getLogger(ClientHandler.class.getName());
    private SSLSocket clientSocket;
    private BufferedReader in;
    private PrintWriter out;
    private String username = null;
    private String sessionId = null;

    public ClientHandler(SSLSocket socket) {
        this.clientSocket = socket;
    }

    @Override
    public void run() {
        try {
            // Initialize input and output streams for communication
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);

            // Prompt client for authentication
            authenticateUser();

            // Process client commands after successful authentication
            String clientMessage;
            while ((clientMessage = in.readLine()) != null) {
                processCommand(clientMessage.trim());
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Client handler encountered an error: ", e);
        } finally {
            // Clean up resources and invalidate session
            SessionManager.invalidateSession(sessionId);
            try {
                if (clientSocket != null && !clientSocket.isClosed()) {
                    clientSocket.close();
                }
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error closing client socket: ", e);
            }
        }
    }

    private void authenticateUser() throws IOException {
        while (sessionId == null) {
            out.println("Please enter command: LOGIN or REGISTER");
            String command = in.readLine();
            if (command == null) break;

            command = command.trim().toUpperCase();

            switch (command) {
                case "LOGIN":
                    out.println("Username:");
                    String user = in.readLine();
                    out.println("Password:");
                    String pass = in.readLine();

                    if (Utils.isValidUsername(user) && Utils.isValidPassword(pass)) {
                        if (AuthenticationService.login(user, pass)) {
                            username = user;
                            sessionId = SessionManager.createSession(username);
                            out.println("Login successful!");
                            logger.info("User logged in: " + username);
                        } else {
                            out.println("Login failed. Incorrect username or password.");
                        }
                    } else {
                        out.println("Invalid username or password format.");
                    }
                    break;

                case "REGISTER":
                    out.println("Choose a username:");
                    String newUser = in.readLine();
                    out.println("Choose a password:");
                    String newPass = in.readLine();

                    if (Utils.isValidUsername(newUser) && Utils.isValidPassword(newPass)) {
                        if (AuthenticationService.register(newUser, newPass)) {
                            out.println("Registration successful! Please login.");
                            logger.info("New user registered: " + newUser);
                        } else {
                            out.println("Registration failed. Username may already exist.");
                        }
                    } else {
                        out.println("Invalid username or password format.");
                    }
                    break;

                default:
                    out.println("Invalid command. Type LOGIN or REGISTER.");
                    break;
            }
        }
    }

    private void processCommand(String command) throws IOException {
        switch (command.toUpperCase()) {
            case "UPLOAD":
                handleUpload();
                break;
            case "DOWNLOAD":
                handleDownload();
                break;
            case "LOGOUT":
                SessionManager.invalidateSession(sessionId);
                sessionId = null;
                username = null;
                out.println("Logged out successfully.");
                authenticateUser();
                break;
            case "EXIT":
                out.println("Goodbye!");
                clientSocket.close();
                break;
            default:
                out.println("Unknown command. Available commands: UPLOAD, DOWNLOAD, LOGOUT, EXIT");
                break;
        }
    }

    private void handleUpload() throws IOException {
        out.println("Enter file name:");
        String fileName = in.readLine();
        if (!Utils.isValidFileName(fileName)) {
            out.println("Invalid file name.");
            return;
        }

        out.println("Enter file content (end with a single line 'EOF'):");
        StringBuilder fileContent = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null && !line.equals("EOF")) {
            fileContent.append(line).append("\n");
        }

        boolean success = FileStorageService.uploadFile(username, fileName, fileContent.toString());
        if (success) {
            out.println("File uploaded successfully.");
            logger.info("User " + username + " uploaded file: " + fileName);
        } else {
            out.println("File upload failed.");
        }
    }

    private void handleDownload() throws IOException {
        out.println("Enter file name to download:");
        String fileName = in.readLine();
        if (!Utils.isValidFileName(fileName)) {
            out.println("Invalid file name.");
            return;
        }

        String fileContent = FileStorageService.downloadFile(username, fileName);
        if (fileContent != null) {
            out.println("File content:");
            out.println(fileContent);
            logger.info("User " + username + " downloaded file: " + fileName);
        } else {
            out.println("File not found or access denied.");
        }
    }
}
