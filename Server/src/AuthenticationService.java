// AuthenticationService.java
import java.sql.*;
import org.mindrot.jbcrypt.BCrypt;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AuthenticationService {
    private static final Logger logger = Logger.getLogger(AuthenticationService.class.getName());

    public static boolean login(String username, String password) {
        if (!Utils.isValidUsername(username) || !Utils.isValidPassword(password)) {
            return false;
        }

        try (Connection conn = DatabaseConnector.getConnection()) {
            String query = "SELECT password FROM users WHERE username = ?";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.setString(1, username);

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String hashedPassword = rs.getString("password");
                // Verify the password using bcrypt
                if (BCrypt.checkpw(password, hashedPassword)) {
                    return true;
                }
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error during login for user: " + username, e);
        }
        return false;
    }

    public static boolean register(String username, String password) {
        if (!Utils.isValidUsername(username) || !Utils.isValidPassword(password)) {
            return false;
        }

        try (Connection conn = DatabaseConnector.getConnection()) {
            // Check if username already exists
            String checkQuery = "SELECT username FROM users WHERE username = ?";
            PreparedStatement checkStmt = conn.prepareStatement(checkQuery);
            checkStmt.setString(1, username);
            ResultSet rs = checkStmt.executeQuery();

            if (rs.next()) {
                // Username already exists
                return false;
            }

            // Hash the password using bcrypt
            String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());

            // Generate a symmetric key for the user
            byte[] symmetricKey = KeyManagementService.generateSymmetricKey();

            // Insert new user into database
            String insertQuery = "INSERT INTO users (username, password, symmetric_key) VALUES (?, ?, ?)";
            PreparedStatement insertStmt = conn.prepareStatement(insertQuery);
            insertStmt.setString(1, username);
            insertStmt.setString(2, hashedPassword);
            insertStmt.setBytes(3, symmetricKey);

            int rowsInserted = insertStmt.executeUpdate();
            return rowsInserted > 0;
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error during registration for user: " + username, e);
        }
        return false;
    }
}
