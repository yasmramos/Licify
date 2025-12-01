package com.licify.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

public class LicenseRevocationManager {

    private String revokedLicenseFile = "revoked.lics";
    private static final LicenseRevocationManager instance = new LicenseRevocationManager();

    // Thread-safe cache with read-write lock for better concurrency
    private final Set<String> revokedLicenses = ConcurrentHashMap.newKeySet();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private Path revocationFilePath;

    // Error messages
    private static final String ERROR_CREATING_FILE = "Error creating revocation file";
    private static final String ERROR_LOADING_REVOCATIONS = "Error loading revoked licenses";
    private static final String ERROR_REVOKING_LICENSE = "Error revoking license";
    private static final String ERROR_CHECKING_REVOCATION = "Error checking license revocation status";

    private LicenseRevocationManager() {
        try {
            this.revocationFilePath = Paths.get(revokedLicenseFile);
            initializeRevocationFile();
            loadRevokedLicenses();
        } catch (Exception e) {
            // Manejo mejorado del error de inicialización
            System.err.println("Warning: Could not initialize revocation manager: " + e.getMessage());
            this.revocationFilePath = Paths.get("revoked.lics"); // fallback
        }
    }

    public static LicenseRevocationManager getInstance() {
        return instance;
    }

    /**
     * Initialize the revocation file if it doesn't exist
     */
    private void initializeRevocationFile() {
        lock.writeLock().lock();
        try {
            if (!Files.exists(revocationFilePath)) {
                // Safe directory creation - handle null parent
                Path parentDir = revocationFilePath.getParent();
                if (parentDir != null && !Files.exists(parentDir)) {
                    Files.createDirectories(parentDir);
                }
                Files.createFile(revocationFilePath);
            }
        } catch (IOException ex) {
            System.err.println(ERROR_CREATING_FILE);
            // Don't throw exception during initialization, just log
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Revoke a specific license
     */
    public boolean revokeLicense(String licenseData) {
        lock.writeLock().lock();
        try {
            String hash = hashLicenseData(licenseData);

            if (revokedLicenses.contains(hash)) {
                return false; // Already revoked
            }

            revokedLicenses.add(hash);

            // Append to file with proper error handling
            Files.write(
                    revocationFilePath,
                    (hash + System.lineSeparator()).getBytes(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND,
                    StandardOpenOption.WRITE
            );

            System.err.println(String.format("License revoked: {0}", hash));
            return true;

        } catch (Exception e) {
            System.err.println(String.format(ERROR_REVOKING_LICENSE, e));
            return false;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Revoke a license by its JSON content
     */
    public boolean revokeLicenseByContent(String licenseJson) {
        return revokeLicense(licenseJson);
    }

    /**
     * Revoke multiple licenses with batch processing
     */
    public int revokeLicenses(List<String> licenseDatas) {
        int revokedCount = 0;
        lock.writeLock().lock();
        try {
            // Collect all hashes first
            Set<String> newHashes = licenseDatas.parallelStream()
                    .map(this::hashLicenseDataSafe)
                    .filter(hash -> hash != null && !revokedLicenses.contains(hash))
                    .collect(Collectors.toSet());

            if (!newHashes.isEmpty()) {
                revokedLicenses.addAll(newHashes);

                // Batch write to file
                String batchContent = newHashes.stream()
                        .collect(Collectors.joining(System.lineSeparator())) + System.lineSeparator();

                Files.write(
                        revocationFilePath,
                        batchContent.getBytes(),
                        StandardOpenOption.CREATE,
                        StandardOpenOption.APPEND,
                        StandardOpenOption.WRITE
                );

                revokedCount = newHashes.size();

                System.err.println(String.format("Revoked {0} licenses in batch", revokedCount));
            }
            return revokedCount;

        } catch (IOException e) {
            System.err.println(String.format("Error batch revoking licenses", e));
            return revokedCount;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Check if a license is revoked
     */
    public boolean isRevoked(String licenseData) {
        lock.readLock().lock();
        try {
            String hash = hashLicenseData(licenseData);
            return revokedLicenses.contains(hash);
        } catch (Exception e) {
            System.err.println(String.format(ERROR_CHECKING_REVOCATION, e));
            return false;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Load revoked licenses from file
     */
    private void loadRevokedLicenses() {
        lock.writeLock().lock();
        try {
            revokedLicenses.clear();
            if (Files.exists(revocationFilePath)) {
                List<String> lines = Files.readAllLines(revocationFilePath);
                revokedLicenses.addAll(lines.parallelStream()
                        .map(String::trim)
                        .filter(line -> !line.isEmpty())
                        .collect(Collectors.toSet()));

                System.err.println(String.format(
                        "Loaded {0} revoked licenses from file",
                        revokedLicenses.size()));
            }
        } catch (IOException e) {
            System.err.println(String.format(ERROR_LOADING_REVOCATIONS, e));
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Generate unique hash for license data
     */
    private String hashLicenseData(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(data.getBytes("UTF-8"));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    /**
     * Safe hash generation that returns null on error
     */
    private String hashLicenseDataSafe(String data) {
        try {
            return hashLicenseData(data);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get all revoked licenses (immutable copy)
     */
    public Set<String> getRevokedLicenses() {
        lock.readLock().lock();
        try {
            return Collections.unmodifiableSet(new HashSet<>(revokedLicenses));
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Get the number of revoked licenses
     */
    public int getRevokedLicenseCount() {
        lock.readLock().lock();
        try {
            return revokedLicenses.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Clear all revocations (for testing only)
     */
    public void clearAllRevocations() {
        lock.writeLock().lock();
        try {
            revokedLicenses.clear();
            Files.deleteIfExists(revocationFilePath);
            initializeRevocationFile();

            System.err.println(String.format("All revocations cleared"));
        } catch (IOException e) {
            System.err.println(String.format("Error clearing revocations", e));
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Check if revocation file exists
     */
    public boolean hasRevocationFile() {
        lock.readLock().lock();
        try {
            return Files.exists(revocationFilePath);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Reload revoked licenses from file (useful if file was modified
     * externally)
     */
    public void reloadRevokedLicenses() {
        lock.writeLock().lock();
        try {
            loadRevokedLicenses();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public String getRevokedLicenseFile() {
        lock.readLock().lock();
        try {
            return revokedLicenseFile;
        } finally {
            lock.readLock().unlock();
        }
    }

    public void setRevokedLicenseFile(String revokedLicenseFile) {
        lock.writeLock().lock();
        try {
            this.revokedLicenseFile = revokedLicenseFile;
            this.revocationFilePath = Paths.get(revokedLicenseFile);

            // Create the file if it doesn't exist with safe directory creation
            if (!Files.exists(revocationFilePath)) {
                Path parentDir = revocationFilePath.getParent();
                if (parentDir != null && !Files.exists(parentDir)) {
                    Files.createDirectories(parentDir);
                }
                Files.createFile(revocationFilePath);
            }

            // Load licenses from the new file
            loadRevokedLicenses();

            System.err.println(String.format("Revocation file changed to: {0}", revokedLicenseFile));

        } catch (IOException ex) {
            System.err.println(String.format("Error setting revocation file", ex));
            // Don't throw exception, just log
        } finally {
            lock.writeLock().unlock();
        }
    }
}
