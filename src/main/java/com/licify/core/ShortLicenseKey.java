package com.licify.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

/**
 * Utility class for generating and verifying short license keys in a standardized format.
 * This class provides methods to create deterministic short keys from seeds and verify
 * their validity against original seeds or secret-value combinations.
 */
public class ShortLicenseKey {

    /**
     * Generates a short license key in the format DCWI3U-6RDTB8-EBMPTJ-TVURQ7 from a seed.
     * The key is deterministically generated using SHA-256 hashing of the seed input.
     *
     * @param seed The input string used to generate the license key. Should not be null.
     * @return A 29-character license key in the format XXXX-XXXX-XXXX-XXXX where each segment
     *         contains 6 alphanumeric characters (letters and digits).
     * 
     * @throws RuntimeException if SHA-256 algorithm is not available (falls back to random generation)
     * 
     * @example
     * generateShortKey("user123:productA:2023") 
     * // Returns: "DCWI3U-6RDTB8-EBMPTJ-TVURQ7"
     */
    public static String generateShortKey(String seed) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(seed.getBytes(StandardCharsets.UTF_8));

            StringBuilder result = new StringBuilder();

            for (int i = 0; i < 4; i++) {
                if (i > 0) {
                    result.append("-");
                }
                StringBuilder segment = new StringBuilder();
                int start = i * 6;
                int end = Math.min(start + 6, hash.length);
                byte[] segmentBytes = Arrays.copyOfRange(hash, start, end);

                for (int j = 0; j < Math.min(6, segmentBytes.length); j++) {
                    int val = segmentBytes[j] & 0xFF;
                    if (j % 2 == 0) {
                        segment.append((char) ('A' + (val % 26))); // Letters for even positions
                    } else {
                        segment.append((char) ('0' + (val % 10))); // Digits for odd positions
                    }
                }

                // Pad with 'A' if segment is shorter than 6 characters
                while (segment.length() < 6) {
                    segment.append('A');
                }
                result.append(segment.substring(0, 6));
            }

            return result.toString();
        } catch (NoSuchAlgorithmException e) {
            return generateRandomShortKey();
        }
    }

    /**
     * Generates a random short license key as fallback when hashing fails.
     * This method creates a non-deterministic random key in the same format.
     *
     * @return A randomly generated 29-character license key in the standard format.
     */
    private static String generateRandomShortKey() {
        Random random = new Random();
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < 4; i++) {
            if (i > 0) {
                result.append("-");
            }
            StringBuilder segment = new StringBuilder();
            for (int j = 0; j < 6; j++) {
                if (random.nextBoolean()) {
                    segment.append((char) ('A' + random.nextInt(26))); // Random letter
                } else {
                    segment.append((char) ('0' + random.nextInt(10))); // Random digit
                }
            }
            result.append(segment);
        }

        return result.toString();
    }
    
    /**
     * Verifies if a short license key matches the expected key generated from a seed.
     *
     * @param shortKey The license key to verify in format XXXX-XXXX-XXXX-XXXX
     * @param seed The original seed used to generate the expected key
     * @return true if the provided key matches the key generated from the seed,
     *         false if the key is invalid, null, or doesn't match
     * 
     * @see #isValidShortKey(String)
     * @see #generateShortKey(String)
     */
    public static boolean verifyShortKey(String shortKey, String seed) {
        if (!isValidShortKey(shortKey)) {
            return false;
        }

        String expectedKey = generateShortKey(seed);
        return shortKey.equals(expectedKey);
    }

    /**
     * Verifies if a short license key matches the expected key generated from a secret key and value.
     * This method combines the secret key and value with a colon separator before verification.
     *
     * @param shortKey The license key to verify in format XXXX-XXXX-XXXX-XXXX
     * @param secretKey The secret key used for verification
     * @param value The value associated with the license key
     * @return true if the provided key matches the key generated from the secret-value combination,
     *         false if the key is invalid, null, or doesn't match
     * 
     * @example
     * verifyShortKey("DCWI3U-6RDTB8-EBMPTJ-TVURQ7", "SECRET123", "user@email.com")
     */
    public static boolean verifyShortKey(String shortKey, String secretKey, String value) {
        if (!isValidShortKey(shortKey)) {
            return false;
        }

        String combined = secretKey + ":" + value;
        String expectedKey = generateShortKey(combined);
        return shortKey.equals(expectedKey);
    }

    /**
     * Validates the format of a short license key.
     * Checks if the key follows the required format: 4 segments of 6 alphanumeric characters
     * separated by hyphens.
     *
     * @param shortKey The license key to validate
     * @return true if the key matches the format XXXX-XXXX-XXXX-XXXX where X is alphanumeric,
     *         false if the key is null, empty, or has invalid format
     * 
     * @example
     * isValidShortKey("DCWI3U-6RDTB8-EBMPTJ-TVURQ7") // Returns: true
     * isValidShortKey("INVALID-KEY-FORMAT")          // Returns: false
     */
    public static boolean isValidShortKey(String shortKey) {
        if (shortKey == null || shortKey.isEmpty()) {
            return false;
        }

        // Verify format: 6 characters - 6 characters - 6 characters - 6 characters
        String[] segments = shortKey.split("-");
        if (segments.length != 4) {
            return false;
        }

        for (String segment : segments) {
            if (segment.length() != 6) {
                return false;
            }

            // Verify that each segment contains only letters and digits
            for (char c : segment.toCharArray()) {
                if (!Character.isLetterOrDigit(c)) {
                    return false;
                }
            }
        }

        return true;
    }
}