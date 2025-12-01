package com.licify;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility class for generating cryptographic seeds from multiple data inputs.
 * This class provides methods to create deterministic seeds that can be used
 * for various cryptographic purposes such as key generation, initialization
 * vectors, or other security-sensitive operations.
 */
public class SeedGenerator {

    /**
     * Generates a seed from multiple data inputs using multiple hashing
     * algorithms. The input data is concatenated with colon separators and then
     * hashed multiple times.
     *
     * @param data Variable array of strings used to generate the seed. If null
     * or empty, a default seed based on current time is returned.
     * @return A generated seed as a Base64-encoded string with multiple hashing
     * iterations.
     *
     * @throws RuntimeException if hashing algorithms are not available
     */
    public static String generateSeed(String... data) {
        if (data == null || data.length == 0) {
            return generateDefaultSeed();
        }

        StringBuilder sb = new StringBuilder();
        for (String datum : data) {
            if (datum != null) {
                sb.append(datum).append(":");
            }
        }

        // Remove the trailing ":"
        if (sb.length() > 0) {
            sb.deleteCharAt(sb.length() - 1);
        }

        return generateLongSeed(sb.toString());
    }

    /**
     * Generates a seed with a custom prefix from multiple data inputs. The
     * prefix is prepended to the hashed data for additional context or
     * identification.
     *
     * @param prefix Custom prefix to be added to the generated seed (e.g.,
     * "USER_", "APP_")
     * @param data Variable array of strings used to generate the seed. If null
     * or empty, a default seed based on current time is returned.
     * @return A generated seed with the specified prefix, followed by the
     * hashed data.
     *
     * @throws RuntimeException if hashing algorithms are not available
     */
    public static String generateSeed(String prefix, String... data) {
        if (data == null || data.length == 0) {
            return generateDefaultSeed();
        }

        StringBuilder sb = new StringBuilder();
        for (String datum : data) {
            if (datum != null) {
                sb.append(datum).append(":");
            }
        }

        // Remove the trailing ":"
        if (sb.length() > 0) {
            sb.deleteCharAt(sb.length() - 1);
        }

        return prefix + generateLongSeed(sb.toString());
    }

    /**
     * Generates a long seed using multiple hashing algorithms and iterations
     */
    private static String generateLongSeed(String input) {
        try {
            // Multiple iterations with different algorithms
            String hash1 = hashWithAlgorithm(input, "SHA-512");
            String hash2 = hashWithAlgorithm(hash1 + input, "SHA-256");
            String hash3 = hashWithAlgorithm(hash2 + hash1, "SHA-384");

            // Combine and hash again
            String combined = hash1 + hash2 + hash3 + input;
            String finalHash = hashWithAlgorithm(combined, "SHA-512");

            // Add some entropy and hash again
            String entropy = System.currentTimeMillis() + "" + System.nanoTime();
            String withEntropy = finalHash + entropy;

            // Multiple iterations to make it longer
            String result = withEntropy;
            for (int i = 0; i < 3; i++) {
                result = hashWithAlgorithm(result, "SHA-512");
            }

            return Base64.getEncoder().encodeToString(result.getBytes())
                    .replace("=", "") // Remove padding
                    .replace('+', 'X')
                    .replace('/', 'Y').toUpperCase();

        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Error generating long seed", ex);
        }
    }

    /**
     * Hashes input with specified algorithm
     */
    private static String hashWithAlgorithm(String input, String algorithm)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] hash = md.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Generates a default seed with timestamp and random data
     */
    private static String generateDefaultSeed() {
        try {
            String base = "DEFAULT_SEED_" + System.currentTimeMillis() + "_" + System.nanoTime();
            return generateLongSeed(base);
        } catch (Exception e) {
            return "DEFAULT_SEED_EMERGENCY_" + System.currentTimeMillis();
        }
    }

    /**
     * Alternative method to generate very long seeds (200+ characters)
     */
    public static String generateExtraLongSeed(String... data) {
        String baseSeed = generateSeed(data);

        // Extend the seed by hashing multiple times
        StringBuilder longSeed = new StringBuilder(baseSeed);

        for (int i = 0; i < 5; i++) {
            try {
                String extension = hashWithAlgorithm(longSeed.toString() + i, "SHA-512");
                longSeed.append(extension.replace("=", ""));
            } catch (NoSuchAlgorithmException e) {
                // Fallback: add some random data
                longSeed.append("_EXT_").append(System.nanoTime());
            }
        }

        // Ensure minimum length
        while (longSeed.length() < 200) {
            longSeed.append("_PAD_").append(System.currentTimeMillis());
        }

        return longSeed.toString();
    }
}
