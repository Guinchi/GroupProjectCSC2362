// SessionManager.java
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class SessionManager {
    private static ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();
    private static final long SESSION_TIMEOUT = TimeUnit.MINUTES.toMillis(30); // 30 minutes

    public static String createSession(String username) {
        String sessionId = UUID.randomUUID().toString();
        Session session = new Session(username, System.currentTimeMillis());
        sessions.put(sessionId, session);
        return sessionId;
    }

    public static String getUsername(String sessionId) {
        Session session = sessions.get(sessionId);
        if (session != null) {
            // Check if session has expired
            if (System.currentTimeMillis() - session.getLastAccessed() > SESSION_TIMEOUT) {
                invalidateSession(sessionId);
                return null;
            } else {
                // Update last accessed time
                session.setLastAccessed(System.currentTimeMillis());
                return session.getUsername();
            }
        }
        return null;
    }

    public static void invalidateSession(String sessionId) {
        sessions.remove(sessionId);
    }

    private static class Session {
        private String username;
        private long lastAccessed;

        public Session(String username, long lastAccessed) {
            this.username = username;
            this.lastAccessed = lastAccessed;
        }

        public String getUsername() {
            return username;
        }

        public long getLastAccessed() {
            return lastAccessed;
        }

        public void setLastAccessed(long lastAccessed) {
            this.lastAccessed = lastAccessed;
        }
    }
}
