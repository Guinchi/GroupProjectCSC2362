// FileStorageService.java
import java.nio.file.*;
import java.sql.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FileStorageService {
    private static final Logger logger = Logger.getLogger(FileStorageService.class.getName());

    public static boolean uploadFile(String username, String fileName, String fileContent) {
        if (!Utils.isValidFileName(fileName)) {
            return false;
        }

        try {
            // Retrieve user's symmetric key
            byte[] symmetricKey = KeyManagementService.getUserSymmetricKey(username);
            if (symmetricKey == null) return false;

            // Encrypt the file content
            byte[] encryptedData = encryptData(fileContent.getBytes("UTF-8"), symmetricKey);

            // Save the encrypted file to the server's file system
            String sanitizedFileName = Paths.get(fileName).getFileName().toString(); // Prevent path traversal
            Path filePath = Paths.get(Config.FILE_STORAGE_PATH, username + "_" + sanitizedFileName);
            Files.write(filePath, encryptedData, StandardOpenOption.CREATE);

            // Store file metadata in the database
            try (Connection conn = DatabaseConnector.getConnection()) {
                String insertQuery = "INSERT INTO files (username, filename) VALUES (?, ?)";
                PreparedStatement stmt = conn.prepareStatement(insertQuery);
                stmt.setString(1, username);
                stmt.setString(2, sanitizedFileName);
                stmt.executeUpdate();
            }

            return true;
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error uploading file for user: " + username, e);
        }
        return false;
    }

    public static String downloadFile(String username, String fileName) {
        if (!Utils.isValidFileName(fileName)) {
            return null;
        }

        try {
            // Verify that the file exists and belongs to the user
            if (!fileExists(username, fileName)) {
                return null;
            }

            // Retrieve user's symmetric key
            byte[] symmetricKey = KeyManagementService.getUserSymmetricKey(username);
            if (symmetricKey == null) return null;

            // Read the encrypted file from the server's file system
            String sanitizedFileName = Paths.get(fileName).getFileName().toString(); // Prevent path traversal
            Path filePath = Paths.get(Config.FILE_STORAGE_PATH, username + "_" + sanitizedFileName);
            byte[] encryptedData = Files.readAllBytes(filePath);

            // Decrypt the file content
            byte[] decryptedData = decryptData(encryptedData, symmetricKey);

            return new String(decryptedData, "UTF-8");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error downloading file for user: " + username, e);
        }
        return null;
    }

    private static boolean fileExists(String username, String fileName) {
        try (Connection conn = DatabaseConnector.getConnection()) {
            String query = "SELECT * FROM files WHERE username = ? AND filename = ?";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.setString(1, username);
            stmt.setString(2, fileName);

            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error checking file existence for user: " + username, e);
        }
        return false;
    }

    private static byte[] encryptData(byte[] data, byte[] key) throws Exception {
        // Generate a random IV
        byte[] iv = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv);

        // Initialize AES cipher in CBC mode with PKCS5 padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
        byte[] encryptedData = cipher.doFinal(data);

        // Prepend IV to encrypted data for use in decryption
        byte[] encryptedDataWithIv = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, encryptedDataWithIv, 0, iv.length);
        System.arraycopy(encryptedData, 0, encryptedDataWithIv, iv.length, encryptedData.length);

        return encryptedDataWithIv;
    }

    private static byte[] decryptData(byte[] data, byte[] key) throws Exception {
        // Extract IV from data
        byte[] iv = Arrays.copyOfRange(data, 0, 16);
        byte[] encryptedData = Arrays.copyOfRange(data, 16, data.length);

        // Initialize AES cipher in CBC mode with PKCS5 padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParams = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
        return cipher.doFinal(encryptedData);
    }
}
