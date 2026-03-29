package com.licify;

import com.licify.core.FloatingLicenseManager;
import com.licify.core.FloatingLicenseManager.ActivationResult;
import com.licify.core.FloatingLicenseManager.SessionInfo;
import org.junit.jupiter.api.*;
import java.nio.file.*;
import java.util.List;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for FloatingLicenseManager.
 */
public class FloatingLicenseManagerTest {
    
    private FloatingLicenseManager manager;
    private Path testSessionsFile;
    
    @BeforeEach
    public void setUp() throws Exception {
        testSessionsFile = Files.createTempFile("floating-sessions", ".json");
        manager = new FloatingLicenseManager(testSessionsFile);
    }
    
    @AfterEach
    public void tearDown() throws Exception {
        if (manager != null) {
            manager.stopCleanupScheduler();
        }
        if (testSessionsFile != null && Files.exists(testSessionsFile)) {
            Files.deleteIfExists(testSessionsFile);
        }
    }
    
    @Test
    @DisplayName("Should activate session when under limit")
    public void testActivateSession_Success() {
        ActivationResult result = manager.activateSession("LICENSE-001", "client-1", 
                                                         "192.168.1.100", 5);
        
        assertTrue(result.isSuccess());
        assertNotNull(result.getSessionId());
        assertEquals("Session activated successfully", result.getMessage());
        assertEquals(1, result.getCurrentUsers());
        assertEquals(5, result.getMaxUsers());
        assertEquals(4, result.getAvailableSlots());
    }
    
    @Test
    @DisplayName("Should reject activation when limit reached")
    public void testActivateSession_LimitReached() {
        // Activate 3 sessions
        manager.activateSession("LICENSE-001", "client-1", "192.168.1.100", 3);
        manager.activateSession("LICENSE-001", "client-2", "192.168.1.101", 3);
        manager.activateSession("LICENSE-001", "client-3", "192.168.1.102", 3);
        
        // Try to activate 4th session
        ActivationResult result = manager.activateSession("LICENSE-001", "client-4", 
                                                         "192.168.1.103", 3);
        
        assertFalse(result.isSuccess());
        assertNull(result.getSessionId());
        assertTrue(result.getMessage().contains("License limit reached"));
        assertEquals(3, result.getCurrentUsers());
        assertEquals(3, result.getMaxUsers());
        assertEquals(0, result.getAvailableSlots());
    }
    
    @Test
    @DisplayName("Should deactivate session successfully")
    public void testDeactivateSession_Success() {
        ActivationResult activateResult = manager.activateSession("LICENSE-001", "client-1", 
                                                                 "192.168.1.100", 5);
        String sessionId = activateResult.getSessionId();
        
        boolean deactivated = manager.deactivateSession(sessionId);
        
        assertTrue(deactivated);
        assertEquals(0, manager.getActiveSessionCount("LICENSE-001"));
    }
    
    @Test
    @DisplayName("Should return false when deactivating non-existent session")
    public void testDeactivateSession_NotFound() {
        boolean deactivated = manager.deactivateSession("non-existent-session");
        assertFalse(deactivated);
    }
    
    @Test
    @DisplayName("Should update heartbeat successfully")
    public void testUpdateHeartbeat_Success() throws InterruptedException {
        ActivationResult activateResult = manager.activateSession("LICENSE-001", "client-1", 
                                                                 "192.168.1.100", 5);
        String sessionId = activateResult.getSessionId();
        
        Thread.sleep(10); // Small delay
        
        boolean updated = manager.updateHeartbeat(sessionId);
        
        assertTrue(updated);
        
        List<SessionInfo> sessions = manager.getActiveSessions("LICENSE-001");
        assertEquals(1, sessions.size());
        assertTrue(sessions.get(0).getLastHeartbeat().isAfter(sessions.get(0).getActivatedAt()));
    }
    
    @Test
    @DisplayName("Should return false when updating heartbeat for non-existent session")
    public void testUpdateHeartbeat_NotFound() {
        boolean updated = manager.updateHeartbeat("non-existent-session");
        assertFalse(updated);
    }
    
    @Test
    @DisplayName("Should get active sessions for license")
    public void testGetActiveSessions() {
        manager.activateSession("LICENSE-001", "client-1", "192.168.1.100", 5);
        manager.activateSession("LICENSE-001", "client-2", "192.168.1.101", 5);
        manager.activateSession("LICENSE-002", "client-3", "192.168.1.102", 5);
        
        List<SessionInfo> sessions1 = manager.getActiveSessions("LICENSE-001");
        List<SessionInfo> sessions2 = manager.getActiveSessions("LICENSE-002");
        
        assertEquals(2, sessions1.size());
        assertEquals(1, sessions2.size());
    }
    
    @Test
    @DisplayName("Should get all active sessions")
    public void testGetAllActiveSessions() {
        manager.activateSession("LICENSE-001", "client-1", "192.168.1.100", 5);
        manager.activateSession("LICENSE-002", "client-2", "192.168.1.101", 5);
        
        Collection<SessionInfo> allSessions = manager.getAllActiveSessions();
        
        assertEquals(2, allSessions.size());
    }
    
    @Test
    @DisplayName("Should cleanup expired sessions")
    public void testCleanupExpiredSessions() throws InterruptedException {
        manager.activateSession("LICENSE-001", "client-1", "192.168.1.100", 5);
        manager.activateSession("LICENSE-001", "client-2", "192.168.1.101", 5);
        
        // Wait and manually cleanup with 0 minutes timeout
        Thread.sleep(10);
        
        int cleaned = manager.cleanupExpiredSessions(0);
        
        assertEquals(2, cleaned);
        assertEquals(0, manager.getActiveSessionCount("LICENSE-001"));
    }
    
    @Test
    @DisplayName("Should clear all sessions")
    public void testClearAllSessions() {
        manager.activateSession("LICENSE-001", "client-1", "192.168.1.100", 5);
        manager.activateSession("LICENSE-002", "client-2", "192.168.1.101", 5);
        
        manager.clearAllSessions();
        
        assertEquals(0, manager.getAllActiveSessions().size());
    }
    
    @Test
    @DisplayName("Should persist and load sessions")
    public void testSessionPersistence() {
        manager.activateSession("LICENSE-001", "client-1", "192.168.1.100", 5);
        manager.activateSession("LICENSE-002", "client-2", "192.168.1.101", 3);
        
        // Create new manager with same file
        FloatingLicenseManager manager2 = new FloatingLicenseManager(testSessionsFile);
        
        assertEquals(2, manager2.getAllActiveSessions().size());
        assertEquals(1, manager2.getActiveSessionCount("LICENSE-001"));
        assertEquals(1, manager2.getActiveSessionCount("LICENSE-002"));
    }
    
    @Test
    @DisplayName("Should handle multiple licenses independently")
    public void testMultipleLicenses() {
        ActivationResult r1 = manager.activateSession("LICENSE-A", "client-1", "192.168.1.100", 2);
        ActivationResult r2 = manager.activateSession("LICENSE-B", "client-2", "192.168.1.101", 2);
        
        assertTrue(r1.isSuccess());
        assertTrue(r2.isSuccess());
        
        assertEquals(1, manager.getActiveSessionCount("LICENSE-A"));
        assertEquals(1, manager.getActiveSessionCount("LICENSE-B"));
        assertEquals(2, manager.getAllActiveSessions().size());
    }
}
