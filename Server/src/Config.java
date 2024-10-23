public class Config {
    // Database config
    public static final String DB_URL = "jdbc:mysql://localhost:3306/your_database?useSSL=false&serverTimezone=UTC";
    public static final String DB_USER = "your_username";
    public static final String DB_PASSWORD = "your_db_password";

    // Server config
    public static final int SERVER_PORT = 8443;

    // SSL config
    public static final String KEYSTORE_PATH = "server.keystore";
    public static final String KEYSTORE_PASSWORD = "your_keystore_password";

    // File storage path
    public static final String FILE_STORAGE_PATH = "file_storage";
}
