import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.security.KeyStore;
import javax.net.ssl.*;
import javax.swing.*;

public class SecureFileClient {

    private JFrame loginFrame;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JButton loginButton;
    private JButton registerButton;

    private SSLSocket sslSocket;
    private DataInputStream in;
    private DataOutputStream out;

    private String currentUser;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new SecureFileClient().createAndShowGUI());
    }

    private void createAndShowGUI() {
        loginFrame = new JFrame("Secure File Client - Login");
        loginFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        loginFrame.setSize(400, 150);
        loginFrame.setLocationRelativeTo(null);

        JPanel panel = new JPanel(new GridLayout(3, 2));
        panel.setBorder(BorderFactory.createEmptyBorder(10,10,10,10));

        panel.add(new JLabel("Username:"));
        usernameField = new JTextField(20);
        panel.add(usernameField);

        panel.add(new JLabel("Password:"));
        passwordField = new JPasswordField(20);
        panel.add(passwordField);

        loginButton = new JButton("Login");
        registerButton = new JButton("Register");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(loginButton);
        buttonPanel.add(registerButton);

        loginFrame.add(panel, BorderLayout.CENTER);
        loginFrame.add(buttonPanel, BorderLayout.SOUTH);
        loginFrame.setVisible(true);

        loginButton.addActionListener(e -> handleLogin());
        registerButton.addActionListener(e -> handleRegister());
    }

    private void handleLogin() {
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());

        if (connectToServer()) {
            try {
                // Read welcome messages from the server
                in.readUTF(); // Welcome message
                in.readUTF(); // Commands message

                // Send LOGIN command
                out.writeUTF("LOGIN " + username + " " + password);
                out.flush();
                String response = in.readUTF();
                if (response.equals("Login successful.")) {
                    currentUser = username;
                    // Proceed to main interface
                    SwingUtilities.invokeLater(() -> showMainInterface());
                    loginFrame.dispose();
                } else {
                    JOptionPane.showMessageDialog(loginFrame, response, "Login Failed", JOptionPane.ERROR_MESSAGE);
                    sslSocket.close();
                }

            } catch (IOException ex) {
                ex.printStackTrace();
                JOptionPane.showMessageDialog(loginFrame, "Error communicating with server.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void handleRegister() {
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());

        if (connectToServer()) {
            try {
                // Read welcome messages from the server
                in.readUTF(); // Welcome message
                in.readUTF(); // Commands message

                // Send REGISTER command
                out.writeUTF("REGISTER " + username + " " + password);
                out.flush();
                String response = in.readUTF();
                if (response.equals("Registration successful. You can now login.")) {
                    JOptionPane.showMessageDialog(loginFrame, response, "Registration Successful", JOptionPane.INFORMATION_MESSAGE);
                    sslSocket.close();
                } else {
                    JOptionPane.showMessageDialog(loginFrame, response, "Registration Failed", JOptionPane.ERROR_MESSAGE);
                    sslSocket.close();
                }

            } catch (IOException ex) {
                ex.printStackTrace();
                JOptionPane.showMessageDialog(loginFrame, "Error communicating with server.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private boolean connectToServer() {
        String serverAddress = "localhost"; 
        int serverPort = 8443;

        try {
            // load server keystore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream trustStoreStream = new FileInputStream("server.keystore")) {
                trustStore.load(trustStoreStream, "Diego241202".toCharArray()); // Use your keystore password
            }

            // Initialize a TrustManagerFactory with the trusted store
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            // Initialize SSLContext with the TrustManager(s) from the TrustManagerFactory
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            // Create an SSLSocketFactory using the SSLContext
            SSLSocketFactory ssf = sslContext.getSocketFactory();

            // Create the socket using the SSLSocketFactory
            sslSocket = (SSLSocket) ssf.createSocket(serverAddress, serverPort);

            in = new DataInputStream(sslSocket.getInputStream());
            out = new DataOutputStream(sslSocket.getOutputStream());

            return true;

        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(loginFrame, "Failed to connect to server.", "Connection Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }

    private void showMainInterface() {
        JFrame mainFrame = new JFrame("Secure File Client - User: " + currentUser);
        mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        mainFrame.setSize(600, 400);
        mainFrame.setLocationRelativeTo(null);

        JPanel panel = new JPanel(new BorderLayout());

        // List of files
        DefaultListModel<String> fileListModel = new DefaultListModel<>();
        JList<String> fileList = new JList<>(fileListModel);
        JScrollPane listScrollPane = new JScrollPane(fileList);
        panel.add(listScrollPane, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel();
        JButton refreshButton = new JButton("Refresh");
        JButton uploadButton = new JButton("Upload");
        JButton downloadButton = new JButton("Download");
        JButton deleteButton = new JButton("Delete");
        JButton logoutButton = new JButton("Logout");

        buttonPanel.add(refreshButton);
        buttonPanel.add(uploadButton);
        buttonPanel.add(downloadButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(logoutButton);

        panel.add(buttonPanel, BorderLayout.SOUTH);

        mainFrame.add(panel);
        mainFrame.setVisible(true);

        refreshButton.addActionListener(e -> refreshFileList(fileListModel));
        uploadButton.addActionListener(e -> handleUpload());
        downloadButton.addActionListener(e -> handleDownload(fileList.getSelectedValue()));
        deleteButton.addActionListener(e -> handleDelete(fileList.getSelectedValue()));
        logoutButton.addActionListener((ActionEvent e) -> {
            try {
                out.writeUTF("EXIT");
                out.flush();
                sslSocket.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
            mainFrame.dispose();
            createAndShowGUI(); // Go back to login screen
        });

        // Initial refresh
        refreshFileList(fileListModel);
    }

    private void refreshFileList(DefaultListModel<String> fileListModel) {
        new Thread(() -> {
            try {
                out.writeUTF("LIST");
                out.flush();
                String response = in.readUTF();
                SwingUtilities.invokeLater(() -> {
                    fileListModel.clear();
                    try {
                        if (response.equals("Your files:")) {
                            String fileName;
                            while (!(fileName = in.readUTF()).equals("END_OF_LIST")) {
                                fileListModel.addElement(fileName);
                            }
                        } else if (response.equals("No files found in your folder.")) {
                            JOptionPane.showMessageDialog(null, response, "Information", JOptionPane.INFORMATION_MESSAGE);
                        } else {
                            JOptionPane.showMessageDialog(null, response, "Error", JOptionPane.ERROR_MESSAGE);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
            } catch (IOException ex) {
                ex.printStackTrace();
                JOptionPane.showMessageDialog(null, "Error communicating with server.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }).start();
    }

    private void handleUpload() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
            File fileToUpload = fileChooser.getSelectedFile();
            long fileSize = fileToUpload.length();

            // Check if the file size exceeds the maximum allowed size (250MB)
            if (fileSize > 250L * 1024 * 1024) {
                JOptionPane.showMessageDialog(null, "Error: File size exceeds the maximum allowed limit of 250MB.", "Upload Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            new Thread(() -> {
                try {
                    out.writeUTF("UPLOAD " + fileToUpload.getName());
                    out.flush();
                    String response = in.readUTF();
                    if (response.equals("Ready to receive file size.")) {
                        // Send file size
                        out.writeLong(fileSize);
                        out.flush();

                        // Receive acknowledgment to proceed
                        response = in.readUTF();
                        if (!response.equals("Proceed with file upload.")) {
                            JOptionPane.showMessageDialog(null, response, "Upload Error", JOptionPane.ERROR_MESSAGE);
                            return;
                        }

                        // Send file data
                        try (FileInputStream fis = new FileInputStream(fileToUpload)) {
                            byte[] buffer = new byte[4096];
                            int bytesRead;
                            while ((bytesRead = fis.read(buffer)) != -1) {
                                out.write(buffer, 0, bytesRead);
                            }
                            out.flush();
                        }

                        String uploadResponse = in.readUTF();
                        JOptionPane.showMessageDialog(null, uploadResponse, "Upload", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(null, response, "Error", JOptionPane.ERROR_MESSAGE);
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Error uploading file.", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }).start();
        }
    }

    private void handleDownload(String fileName) {
        if (fileName == null) {
            JOptionPane.showMessageDialog(null, "Please select a file to download.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        new Thread(() -> {
            try {
                out.writeUTF("DOWNLOAD " + fileName);
                out.flush();
                String response = in.readUTF();
                if (response.equals("READY")) {
                    long fileSize = in.readLong();

                    JFileChooser fileChooser = new JFileChooser();
                    fileChooser.setSelectedFile(new File(fileName));
                    int result = fileChooser.showSaveDialog(null);
                    if (result == JFileChooser.APPROVE_OPTION) {
                        File saveFile = fileChooser.getSelectedFile();

                        try (FileOutputStream fos = new FileOutputStream(saveFile)) {
                            byte[] buffer = new byte[4096];
                            long totalBytesRead = 0;
                            int bytesRead;

                            while (totalBytesRead < fileSize && (bytesRead = in.read(buffer, 0, (int) Math.min(buffer.length, fileSize - totalBytesRead))) != -1) {
                                fos.write(buffer, 0, bytesRead);
                                totalBytesRead += bytesRead;
                            }
                        }
                        JOptionPane.showMessageDialog(null, "File downloaded successfully.", "Download", JOptionPane.INFORMATION_MESSAGE);
                    }
                } else {
                    JOptionPane.showMessageDialog(null, response, "Error", JOptionPane.ERROR_MESSAGE);
                }
            } catch (IOException ex) {
                ex.printStackTrace();
                JOptionPane.showMessageDialog(null, "Error downloading file.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }).start();
    }

    private void handleDelete(String fileName) {
        if (fileName == null) {
            JOptionPane.showMessageDialog(null, "Please select a file to delete.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        new Thread(() -> {
            try {
                out.writeUTF("DELETE " + fileName);
                out.flush();
                String response = in.readUTF();
                JOptionPane.showMessageDialog(null, response, "Delete", JOptionPane.INFORMATION_MESSAGE);
                // Refresh file list after deletion
                refreshFileList(new DefaultListModel<>());
            } catch (IOException ex) {
                ex.printStackTrace();
                JOptionPane.showMessageDialog(null, "Error deleting file.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }).start();
    }
}
