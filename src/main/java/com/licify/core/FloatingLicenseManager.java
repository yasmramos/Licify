package com.licify.core;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.*;
import java.util.stream.Collectors;

/**
 * Manages floating (network) licenses with concurrent user limits.
 * Provides session tracking, activation/deactivation, and automatic cleanup.
 */
public class FloatingLicenseManager {
    
    private static final String DEFAULT_SESSIONS_FILE = "floating-sessions.json";
    private final ConcurrentMap<String, SessionInfo> activeSessions;
    private final ReadWriteLock lock;
    private final Path sessionsFilePath;
    private final ScheduledExecutorService cleanupScheduler;
    private volatile boolean schedulerRunning;
    
    /**
     * Represents an active license session.
     */
    public static class SessionInfo {
        private final String sessionId;
        private final String licenseId;
        private final String clientId;
        private final String clientHost;
        private final LocalDateTime activatedAt;
        private LocalDateTime lastHeartbeat;
        private final int maxUsers;
        
        public SessionInfo(String sessionId, String licenseId, String clientId, 
                          String clientHost, int maxUsers) {
            this.sessionId = sessionId;
            this.licenseId = licenseId;
            this.clientId = clientId;
            this.clientHost = clientHost;
            this.activatedAt = LocalDateTime.now();
            this.lastHeartbeat = LocalDateTime.now();
            this.maxUsers = maxUsers;
        }
        
        public void updateHeartbeat() {
            this.lastHeartbeat = LocalDateTime.now();
        }
        
        public String getSessionId() { return sessionId; }
        public String getLicenseId() { return licenseId; }
        public String getClientId() { return clientId; }
        public String getClientHost() { return clientHost; }
        public LocalDateTime getActivatedAt() { return activatedAt; }
        public LocalDateTime getLastHeartbeat() { return lastHeartbeat; }
        public int getMaxUsers() { return maxUsers; }
        
        public long getIdleTimeMinutes() {
            return java.time.Duration.between(lastHeartbeat, LocalDateTime.now()).toMinutes();
        }
    }
    
    /**
     * Result of a license activation attempt.
     */
    public static class ActivationResult {
        private final boolean success;
        private final String sessionId;
        private final String message;
        private final int currentUsers;
        private final int maxUsers;
        
        public ActivationResult(boolean success, String sessionId, String message, 
                               int currentUsers, int maxUsers) {
            this.success = success;
            this.sessionId = sessionId;
            this.message = message;
            this.currentUsers = currentUsers;
            this.maxUsers = maxUsers;
        }
        
        public boolean isSuccess() { return success; }
        public String getSessionId() { return sessionId; }
        public String getMessage() { return message; }
        public int getCurrentUsers() { return currentUsers; }
        public int getMaxUsers() { return maxUsers; }
        public int getAvailableSlots() { return Math.max(0, maxUsers - currentUsers); }
    }
    
    public FloatingLicenseManager() {
        this(Paths.get(DEFAULT_SESSIONS_FILE));
    }
    
    public FloatingLicenseManager(Path sessionsFilePath) {
        this.sessionsFilePath = sessionsFilePath;
        this.activeSessions = new ConcurrentHashMap<>();
        this.lock = new ReentrantReadWriteLock();
        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "FloatingLicense-Cleanup");
            t.setDaemon(true);
            return t;
        });
        this.schedulerRunning = false;
        loadSessions();
    }
    
    /**
     * Starts the automatic cleanup scheduler.
     * @param heartbeatTimeoutMinutes Sessions without heartbeat for this duration are removed
     */
    public void startCleanupScheduler(int heartbeatTimeoutMinutes) {
        if (schedulerRunning) {
            return;
        }
        
        schedulerRunning = true;
        cleanupScheduler.scheduleAtFixedRate(() -> {
            cleanupExpiredSessions(heartbeatTimeoutMinutes);
        }, heartbeatTimeoutMinutes, heartbeatTimeoutMinutes, TimeUnit.MINUTES);
    }
    
    /**
     * Stops the cleanup scheduler.
     */
    public void stopCleanupScheduler() {
        schedulerRunning = false;
        cleanupScheduler.shutdown();
        try {
            if (!cleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupScheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Activates a floating license session.
     * @param licenseId Unique license identifier
     * @param clientId Client identifier requesting the license
     * @param clientHost Client hostname or IP
     * @param maxUsers Maximum concurrent users allowed
     * @return ActivationResult with success status and session info
     */
    public ActivationResult activateSession(String licenseId, String clientId, 
                                           String clientHost, int maxUsers) {
        lock.readLock().lock();
        try {
            // Count active sessions for this license
            long currentUsers = activeSessions.values().stream()
                .filter(s -> s.getLicenseId().equals(licenseId))
                .count();
            
            if (currentUsers >= maxUsers) {
                return new ActivationResult(false, null, 
                    "License limit reached: " + currentUsers + "/" + maxUsers + " users active",
                    (int)currentUsers, maxUsers);
            }
            
            // Create new session
            String sessionId = UUID.randomUUID().toString();
            SessionInfo session = new SessionInfo(sessionId, licenseId, clientId, 
                                                  clientHost, maxUsers);
            activeSessions.put(sessionId, session);
            saveSessions();
            
            return new ActivationResult(true, sessionId, "Session activated successfully",
                                       (int)currentUsers + 1, maxUsers);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Deactivates a license session.
     * @param sessionId Session identifier to deactivate
     * @return true if session was found and removed, false otherwise
     */
    public boolean deactivateSession(String sessionId) {
        lock.writeLock().lock();
        try {
            SessionInfo removed = activeSessions.remove(sessionId);
            if (removed != null) {
                saveSessions();
                return true;
            }
            return false;
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Updates the heartbeat for a session.
     * @param sessionId Session identifier
     * @return true if session exists and heartbeat was updated
     */
    public boolean updateHeartbeat(String sessionId) {
        SessionInfo session = activeSessions.get(sessionId);
        if (session != null) {
            session.updateHeartbeat();
            return true;
        }
        return false;
    }
    
    /**
     * Gets all active sessions for a license.
     * @param licenseId License identifier
     * @return List of active session info
     */
    public List<SessionInfo> getActiveSessions(String licenseId) {
        lock.readLock().lock();
        try {
            return activeSessions.values().stream()
                .filter(s -> s.getLicenseId().equals(licenseId))
                .collect(Collectors.toList());
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Gets all active sessions across all licenses.
     * @return Collection of all active sessions
     */
    public Collection<SessionInfo> getAllActiveSessions() {
        return Collections.unmodifiableCollection(activeSessions.values());
    }
    
    /**
     * Gets the count of active sessions for a license.
     * @param licenseId License identifier
     * @return Number of active sessions
     */
    public int getActiveSessionCount(String licenseId) {
        return (int) activeSessions.values().stream()
            .filter(s -> s.getLicenseId().equals(licenseId))
            .count();
    }
    
    /**
     * Gets available slots for a license.
     * @param licenseId License identifier
     * @param maxUsers Maximum allowed users
     * @return Number of available slots
     */
    public int getAvailableSlots(String licenseId, int maxUsers) {
        int activeCount = getActiveSessionCount(licenseId);
        return Math.max(0, maxUsers - activeCount);
    }
    
    /**
     * Cleans up expired sessions based on heartbeat timeout.
     * @param heartbeatTimeoutMinutes Timeout in minutes
     * @return Number of sessions removed
     */
    public int cleanupExpiredSessions(int heartbeatTimeoutMinutes) {
        lock.writeLock().lock();
        try {
            LocalDateTime cutoff = LocalDateTime.now().minusMinutes(heartbeatTimeoutMinutes);
            List<String> expiredSessions = activeSessions.values().stream()
                .filter(s -> s.getLastHeartbeat().isBefore(cutoff))
                .map(SessionInfo::getSessionId)
                .collect(Collectors.toList());
            
            for (String sessionId : expiredSessions) {
                activeSessions.remove(sessionId);
            }
            
            if (!expiredSessions.isEmpty()) {
                saveSessions();
            }
            
            return expiredSessions.size();
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Clears all active sessions.
     */
    public void clearAllSessions() {
        lock.writeLock().lock();
        try {
            activeSessions.clear();
            saveSessions();
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Saves sessions to JSON file.
     */
    private void saveSessions() {
        try {
            StringBuilder json = new StringBuilder("[\n");
            Iterator<SessionInfo> iterator = activeSessions.values().iterator();
            while (iterator.hasNext()) {
                SessionInfo session = iterator.next();
                json.append("  {\n");
                json.append("    \"sessionId\": \"").append(session.getSessionId()).append("\",\n");
                json.append("    \"licenseId\": \"").append(session.getLicenseId()).append("\",\n");
                json.append("    \"clientId\": \"").append(session.getClientId()).append("\",\n");
                json.append("    \"clientHost\": \"").append(session.getClientHost()).append("\",\n");
                json.append("    \"activatedAt\": \"").append(session.getActivatedAt()).append("\",\n");
                json.append("    \"lastHeartbeat\": \"").append(session.getLastHeartbeat()).append("\",\n");
                json.append("    \"maxUsers\": ").append(session.getMaxUsers()).append("\n");
                json.append("  }");
                if (iterator.hasNext()) {
                    json.append(",");
                }
                json.append("\n");
            }
            json.append("]");
            
            Files.writeString(sessionsFilePath, json.toString());
        } catch (IOException e) {
            System.err.println("Failed to save sessions: " + e.getMessage());
        }
    }
    
    /**
     * Loads sessions from JSON file.
     */
    private void loadSessions() {
        if (!Files.exists(sessionsFilePath)) {
            return;
        }
        
        try {
            String content = Files.readString(sessionsFilePath);
            // Simple JSON parsing (in production, use Jackson or Gson)
            activeSessions.clear();
            
            // Extract session objects using regex
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                "\\{[^}]*\"sessionId\"\\s*:\\s*\"([^\"]+)\"[^}]*\"licenseId\"\\s*:\\s*\"([^\"]+)\"[^}]*\"clientId\"\\s*:\\s*\"([^\"]+)\"[^}]*\"clientHost\"\\s*:\\s*\"([^\"]+)\"[^}]*\"maxUsers\"\\s*:\\s*(\\d+)[^}]*\\}",
                java.util.regex.Pattern.DOTALL
            );
            
            java.util.regex.Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                String sessionId = matcher.group(1);
                String licenseId = matcher.group(2);
                String clientId = matcher.group(3);
                String clientHost = matcher.group(4);
                int maxUsers = Integer.parseInt(matcher.group(5));
                
                SessionInfo session = new SessionInfo(sessionId, licenseId, clientId, 
                                                      clientHost, maxUsers);
                activeSessions.put(sessionId, session);
            }
        } catch (IOException e) {
            System.err.println("Failed to load sessions: " + e.getMessage());
        }
    }
}
