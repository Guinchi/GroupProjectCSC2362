// DatabaseConnector.java
import java.sql.*;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DatabaseConnector {
    private static final Logger logger = Logger.getLogger(DatabaseConnector.class.getName());

    public static Connection getConnection() throws SQLException {
        try {
            // Optionally load the JDBC driver (depends on the JDBC version)
            // Class.forName("com.mysql.cj.jdbc.Driver");

            Properties connectionProps = new Properties();
            connectionProps.put("user", Config.DB_USERNAME);
            connectionProps.put("password", Config.DB_PASSWORD);
            // Add SSL properties if needed
            // connectionProps.put("useSSL", "true");
            // connectionProps.put("verifyServerCertificate", "false");

            return DriverManager.getConnection(Config.DB_URL, connectionProps);
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Error connecting to the database: ", e);
            throw e;
        }
    }
}
