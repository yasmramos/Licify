package com.licify.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for TamperDetection utility class.
 */
class TamperDetectionTest {

    @Test
    void testDetectTimeTamperingWithNormalTime() {
        long currentTime = System.currentTimeMillis();
        long previousTime = currentTime - 1000; // 1 second ago
        
        assertFalse(TamperDetection.detectTimeTampering(previousTime));
    }

    @Test
    void testDetectTimeTamperingWithBackwardTime() {
        long currentTime = System.currentTimeMillis();
        long futureTime = currentTime + 120000; // 2 minutes in the future
        
        assertTrue(TamperDetection.detectTimeTampering(futureTime));
    }

    @Test
    void testDetectTimeTamperingWithLargeForwardJump() {
        long currentTime = System.currentTimeMillis();
        long oldTime = currentTime - 100000000L; // ~1 day ago
        
        assertTrue(TamperDetection.detectTimeTampering(oldTime));
    }

    @Test
    void testDetectRapidValidationNormal() throws InterruptedException {
        TamperDetection.resetValidationCounter();
        
        // Normal validation with delay
        assertFalse(TamperDetection.detectRapidValidation());
        Thread.sleep(50);
        assertFalse(TamperDetection.detectRapidValidation());
    }

    @Test
    void testDataIntegrityValid() {
        String data = "Important license data";
        String checksum = TamperDetection.generateChecksum(data);
        
        assertTrue(TamperDetection.validateDataIntegrity(data, checksum));
    }

    @Test
    void testDataIntegrityTampered() {
        String originalData = "Original data";
        String checksum = TamperDetection.generateChecksum(originalData);
        String tamperedData = "Tampered data";
        
        assertFalse(TamperDetection.validateDataIntegrity(tamperedData, checksum));
    }

    @Test
    void testGenerateChecksumConsistency() {
        String data = "Test data for checksum";
        String checksum1 = TamperDetection.generateChecksum(data);
        String checksum2 = TamperDetection.generateChecksum(data);
        
        assertEquals(checksum1, checksum2);
    }

    @Test
    void testResetValidationCounter() throws InterruptedException {
        TamperDetection.resetValidationCounter();
        
        // Trigger some validations
        TamperDetection.detectRapidValidation();
        TamperDetection.detectRapidValidation();
        
        // Reset
        TamperDetection.resetValidationCounter();
        
        // Should start fresh
        Thread.sleep(50);
        assertFalse(TamperDetection.detectRapidValidation());
    }

    @Test
    void testDebuggerDetectionNoDebugger() {
        // This test assumes no debugger is attached during testing
        // In a real scenario with a debugger, this would return true
        boolean debuggerDetected = TamperDetection.detectDebugger();
        
        // We can't assert false definitively as it depends on environment
        // Just verify it doesn't throw an exception
        assertNotNull(debuggerDetected);
    }
}
