package com.licify.security;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Provides tamper detection mechanisms for license validation.
 * Detects common tampering attempts like time manipulation, debuggers, and memory modification.
 */
public class TamperDetection {

    private static final AtomicInteger validationCounter = new AtomicInteger(0);
    private static volatile long lastValidationTime = 0;
    private static volatile int consecutiveRapidValidations = 0;

    /**
     * Checks for time manipulation attempts by validating system time consistency.
     * 
     * @param previousTimestamp The timestamp from the last validation
     * @return true if time manipulation is detected, false otherwise
     */
    public static boolean detectTimeTampering(long previousTimestamp) {
        long currentTime = System.currentTimeMillis();
        
        // Check if time went backwards significantly (more than 1 minute)
        if (currentTime < previousTimestamp - 60000) {
            return true;
        }
        
        // Check if time jumped forward unreasonably (more than 1 day in a single validation cycle)
        if (currentTime > previousTimestamp + 86400000L) {
            return true;
        }
        
        return false;
    }

    /**
     * Detects rapid-fire validation attempts that might indicate automated attacks.
     * 
     * @return true if suspicious rapid validation pattern is detected
     */
    public static boolean detectRapidValidation() {
        long currentTime = System.currentTimeMillis();
        int currentCount = validationCounter.incrementAndGet();
        
        if (lastValidationTime == 0) {
            lastValidationTime = currentTime;
            consecutiveRapidValidations = 0;
            return false;
        }
        
        long timeDiff = currentTime - lastValidationTime;
        lastValidationTime = currentTime;
        
        // If validations happen within 10ms of each other repeatedly, it's suspicious
        if (timeDiff < 10) {
            consecutiveRapidValidations++;
            if (consecutiveRapidValidations > 5) {
                return true;
            }
        } else {
            consecutiveRapidValidations = 0;
        }
        
        return false;
    }

    /**
     * Simple debugger detection using thread timing.
     * Note: This is a basic check and can be bypassed by sophisticated debuggers.
     * 
     * @return true if debugger presence is suspected
     */
    public static boolean detectDebugger() {
        try {
            long start = System.nanoTime();
            
            // Perform a simple operation
            int sum = 0;
            for (int i = 0; i < 1000; i++) {
                sum += i;
            }
            
            long end = System.nanoTime();
            long duration = end - start;
            
            // If the operation takes unusually long, a debugger might be attached
            // Threshold is set high to avoid false positives on slow systems
            if (duration > 1000000000L) { // 1 second in nanoseconds
                return true;
            }
        } catch (Exception e) {
            // If we can't access thread bean, assume no debugger
            return false;
        }
        
        return false;
    }

    /**
     * Validates data integrity using checksum.
     * 
     * @param data The data to validate
     * @param expectedChecksum The expected checksum value
     * @return true if data integrity is intact
     */
    public static boolean validateDataIntegrity(String data, String expectedChecksum) {
        String actualChecksum = Integer.toHexString(data.hashCode());
        return actualChecksum.equals(expectedChecksum);
    }

    /**
     * Generates a checksum for data integrity verification.
     * 
     * @param data The data to generate checksum for
     * @return The checksum string
     */
    public static String generateChecksum(String data) {
        return Integer.toHexString(data.hashCode());
    }

    /**
     * Resets the validation counter. Should be called periodically or on license renewal.
     */
    public static void resetValidationCounter() {
        validationCounter.set(0);
        consecutiveRapidValidations = 0;
        lastValidationTime = 0;
    }
}
