import java.io.IOException;
import java.io.ObjectInputFilter.Config;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
public class ServerMain {
    private static final Logger logger = Logger.getLogger(ServerMain.class.getName());

    public static void main(String[] args) {
        SSLServerSocket serverSocket = null;    
        try {
            // Load SSL context with server keystore
            SSLContext sslContext = SSLContext.getInstance("TLS");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore ks = KeyStore.getInstance("JKS");

            // Load the server keystore
            char[] passphrase = Config.KEYSTORE_PASSWORD.toCharArray();
            ks.load(new java.io.FileInputStream(Config.KEYSTORE_PATH), passphrase);
            kmf.init(ks, passphrase);
            sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());

            // Continuously accept client connections
            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                logger.info("New client connected: " + clientSocket.getInetAddress());

                // Start a new thread to handle each client
                new Thread(new ClientHandler(clientSocket)).start();    
            }
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | UnrecoverableKeyException | KeyManagementException e) {
            logger.log(Level.SEVERE, "Server encountered an error: ", e);
        } finally {
            // ensure server socket is closed
            if (serverSocket != null && !serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                    logger.log(Level.WARNING, "Error closing server socket: ", e);
                }
            }
        }
    }


}