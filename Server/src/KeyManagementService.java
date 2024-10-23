// KeyManagementService.java
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyManagementService {
    private static final Logger logger = Logger.getLogger(KeyManagementService.class.getName());

    public static byte[] generateSymmetricKey() {
        try {
            // Generate an AES key with a secure random source
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = new SecureRandom();
            keyGen.init(128, secureRandom); // 128-bit AES
            SecretKey secretKey = keyGen.generateKey();
            return secretKey.getEncoded();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error generating symmetric key: ", e);
        }
        return null;
    }

    public static byte[] getUserSymmetricKey(String username) {
        try (Connection conn = DatabaseConnector.getConnection()) {
            String query = "SELECT symmetric_key FROM users WHERE username = ?";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.setString(1, username);

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getBytes("symmetric_key");
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error retrieving symmetric key for user: " + username, e);
        }
        return null;
    }
}
