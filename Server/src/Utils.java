// Utils.java
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class Utils {
    private static final Logger logger = Logger.getLogger(Utils.class.getName());

    // Username must be alphanumeric and between 3 and 20 characters
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9]{3,20}$");

    // Password must be at least 6 characters
    private static final int MIN_PASSWORD_LENGTH = 6;

    // File name must not contain illegal characters
    private static final Pattern FILENAME_PATTERN = Pattern.compile("^[^\\\\/:*?\"<>|]{1,255}$");

    public static boolean isValidUsername(String username) {
        return username != null && USERNAME_PATTERN.matcher(username).matches();
    }

    public static boolean isValidPassword(String password) {
        return password != null && password.length() >= MIN_PASSWORD_LENGTH;
    }

    public static boolean isValidFileName(String fileName) {
        return fileName != null && FILENAME_PATTERN.matcher(fileName).matches();
    }

    public static void log(String message) {
        logger.info(message);
    }
}
