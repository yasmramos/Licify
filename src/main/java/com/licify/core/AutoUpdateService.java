package com.licify.core;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.function.Supplier;

/**
 * Automatic update service with secure version checking and download.
 * Supports version comparison, integrity validation, and callback notifications.
 */
public class AutoUpdateService {
    
    private static final String DEFAULT_UPDATE_DIR = "updates";
    private final String currentVersion;
    private final String updateServerUrl;
    private final Path updateDirectory;
    private final MessageDigest digest;
    
    /**
     * Update information returned by the server.
     */
    public static class UpdateInfo {
        private final String version;
        private final String downloadUrl;
        private final String checksum;
        private final long fileSize;
        private final String releaseNotes;
        private final boolean critical;
        
        public UpdateInfo(String version, String downloadUrl, String checksum,
                         long fileSize, String releaseNotes, boolean critical) {
            this.version = version;
            this.downloadUrl = downloadUrl;
            this.checksum = checksum;
            this.fileSize = fileSize;
            this.releaseNotes = releaseNotes;
            this.critical = critical;
        }
        
        public String getVersion() { return version; }
        public String getDownloadUrl() { return downloadUrl; }
        public String getChecksum() { return checksum; }
        public long getFileSize() { return fileSize; }
        public String getReleaseNotes() { return releaseNotes; }
        public boolean isCritical() { return critical; }
    }
    
    /**
     * Progress listener for download operations.
     */
    public interface ProgressListener {
        void onDownloadStarted();
        void onProgress(long bytesDownloaded, long totalBytes, int percentage);
        void onComplete(Path downloadedFile);
        void onError(String error);
    }
    
    /**
     * Update callback for notification events.
     */
    public interface UpdateCallback {
        void onUpdateAvailable(UpdateInfo info);
        void onDownloadStarted();
        void onDownloadComplete(Path file);
        void onInstallationStarted();
        void onInstallationComplete(boolean success);
        void onError(String error);
    }
    
    public AutoUpdateService(String currentVersion, String updateServerUrl) {
        this(currentVersion, updateServerUrl, Paths.get(DEFAULT_UPDATE_DIR));
    }
    
    public AutoUpdateService(String currentVersion, String updateServerUrl, Path updateDirectory) {
        this.currentVersion = currentVersion;
        this.updateServerUrl = updateServerUrl.endsWith("/") ? 
            updateServerUrl.substring(0, updateServerUrl.length() - 1) : updateServerUrl;
        this.updateDirectory = updateDirectory;
        
        try {
            this.digest = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize SHA-256 digest", e);
        }
        
        // Ensure update directory exists
        if (!Files.exists(updateDirectory)) {
            try {
                Files.createDirectories(updateDirectory);
            } catch (IOException e) {
                System.err.println("Failed to create update directory: " + e.getMessage());
            }
        }
    }
    
    /**
     * Checks if a new version is available.
     * @return UpdateInfo if update available, null otherwise
     */
    public UpdateInfo checkForUpdates() {
        try {
            URL url = new URL(updateServerUrl + "/version.json");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            
            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                System.err.println("Failed to check updates: HTTP " + responseCode);
                return null;
            }
            
            String response = readResponse(conn.getInputStream());
            UpdateInfo info = parseUpdateInfo(response);
            
            if (info != null && isNewerVersion(info.getVersion())) {
                return info;
            }
            
            return null;
        } catch (IOException e) {
            System.err.println("Error checking for updates: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Downloads the update file with progress tracking.
     * @param info Update information
     * @param listener Progress listener
     * @return Downloaded file path
     */
    public Path downloadUpdate(UpdateInfo info, ProgressListener listener) {
        try {
            if (listener != null) {
                listener.onDownloadStarted();
            }
            
            URL url = new URL(info.getDownloadUrl());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(30000);
            
            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("Download failed: HTTP " + responseCode);
            }
            
            long contentLength = conn.getContentLengthLong();
            Path tempFile = updateDirectory.resolve("update_" + info.getVersion() + ".tmp");
            
            try (InputStream in = conn.getInputStream();
                 OutputStream out = Files.newOutputStream(tempFile)) {
                
                byte[] buffer = new byte[8192];
                long totalBytes = 0;
                int bytesRead;
                
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                    totalBytes += bytesRead;
                    
                    if (listener != null && contentLength > 0) {
                        int percentage = (int)((totalBytes * 100) / contentLength);
                        listener.onProgress(totalBytes, contentLength, percentage);
                    }
                }
            }
            
            // Rename to final file
            Path finalFile = updateDirectory.resolve("update_" + info.getVersion() + ".jar");
            Files.move(tempFile, finalFile, StandardCopyOption.REPLACE_EXISTING);
            
            // Verify checksum
            if (!verifyChecksum(finalFile, info.getChecksum())) {
                Files.deleteIfExists(finalFile);
                throw new IOException("Checksum verification failed");
            }
            
            if (listener != null) {
                listener.onComplete(finalFile);
            }
            
            return finalFile;
            
        } catch (IOException e) {
            if (listener != null) {
                listener.onError(e.getMessage());
            }
            throw new RuntimeException("Download failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Verifies file checksum.
     * @param file File to verify
     * @param expectedChecksum Expected SHA-256 checksum (hex)
     * @return true if checksum matches
     */
    public boolean verifyChecksum(Path file, String expectedChecksum) {
        try {
            byte[] fileBytes = Files.readAllBytes(file);
            byte[] hash = digest.digest(fileBytes);
            String actualChecksum = bytesToHex(hash);
            return actualChecksum.equalsIgnoreCase(expectedChecksum);
        } catch (IOException e) {
            System.err.println("Failed to verify checksum: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Installs the update by running the installer callback.
     * @param updateFile Update file path
     * @param installer Installer callback
     * @return true if installation successful
     */
    public boolean installUpdate(Path updateFile, Supplier<Boolean> installer) {
        try {
            if (!Files.exists(updateFile)) {
                System.err.println("Update file not found: " + updateFile);
                return false;
            }
            
            return installer.get();
            
        } catch (Exception e) {
            System.err.println("Installation failed: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Gets the current version.
     * @return Current version string
     */
    public String getCurrentVersion() {
        return currentVersion;
    }
    
    /**
     * Compares two version strings.
     * @param v1 First version
     * @param v2 Second version
     * @return negative if v1 < v2, 0 if equal, positive if v1 > v2
     */
    public static int compareVersions(String v1, String v2) {
        String[] parts1 = v1.replaceAll("[^0-9.]", "").split("\\.");
        String[] parts2 = v2.replaceAll("[^0-9.]", "").split("\\.");
        
        int maxLen = Math.max(parts1.length, parts2.length);
        
        for (int i = 0; i < maxLen; i++) {
            int num1 = i < parts1.length ? Integer.parseInt(parts1[i]) : 0;
            int num2 = i < parts2.length ? Integer.parseInt(parts2[i]) : 0;
            
            if (num1 != num2) {
                return Integer.compare(num1, num2);
            }
        }
        
        return 0;
    }
    
    /**
     * Checks if provided version is newer than current.
     * @param newVersion Version to check
     * @return true if newVersion is newer
     */
    private boolean isNewerVersion(String newVersion) {
        return compareVersions(newVersion, currentVersion) > 0;
    }
    
    /**
     * Parses update info from JSON response.
     * @param json JSON string
     * @return UpdateInfo object
     */
    private UpdateInfo parseUpdateInfo(String json) {
        try {
            // Simple JSON parsing (in production, use Jackson or Gson)
            String version = extractJsonValue(json, "version");
            String downloadUrl = extractJsonValue(json, "downloadUrl");
            String checksum = extractJsonValue(json, "checksum");
            String releaseNotes = extractJsonValue(json, "releaseNotes");
            boolean critical = json.contains("\"critical\":true");
            
            long fileSize = 0;
            int fileSizeStart = json.indexOf("\"fileSize\":");
            if (fileSizeStart != -1) {
                int valueStart = fileSizeStart + 11;
                int valueEnd = json.indexOf(",", valueStart);
                if (valueEnd == -1) valueEnd = json.indexOf("}", valueStart);
                if (valueEnd != -1) {
                    fileSize = Long.parseLong(json.substring(valueStart, valueEnd).trim());
                }
            }
            
            return new UpdateInfo(version, downloadUrl, checksum, fileSize, 
                                 releaseNotes, critical);
        } catch (Exception e) {
            System.err.println("Failed to parse update info: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Extracts a string value from JSON.
     * @param json JSON string
     * @param key Key to extract
     * @return Value string
     */
    private String extractJsonValue(String json, String key) {
        String searchKey = "\"" + key + "\":";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1) return "";
        
        int valueStart = json.indexOf("\"", keyIndex + searchKey.length()) + 1;
        if (valueStart == 0) return "";
        
        int valueEnd = json.indexOf("\"", valueStart);
        if (valueEnd == -1) return "";
        
        return json.substring(valueStart, valueEnd);
    }
    
    /**
     * Reads response from input stream.
     * @param stream Input stream
     * @return Response string
     */
    private String readResponse(InputStream stream) throws IOException {
        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }
        return response.toString();
    }
    
    /**
     * Converts byte array to hex string.
     * @param bytes Byte array
     * @return Hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
