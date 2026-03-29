package com.licify.analytics;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks license usage analytics including activations, validations, and geographic distribution.
 * Provides insights for license administrators to understand usage patterns.
 */
public class LicenseAnalytics {

    private static final String ANALYTICS_FILE = "license_analytics.json";
    private final Map<String, AnalyticsData> analyticsMap = new ConcurrentHashMap<>();
    private final Path storagePath;

    /**
     * Inner class to hold analytics data for a specific license.
     */
    public static class AnalyticsData {
        public String licenseKey;
        public int validationCount = 0;
        public int activationCount = 0;
        public int deactivationCount = 0;
        public long firstActivationTime = 0;
        public long lastValidationTime = 0;
        public Map<String, Integer> hardwareIdUsage = new HashMap<>();
        public List<String> validationHistory = new ArrayList<>();

        public AnalyticsData(String licenseKey) {
            this.licenseKey = licenseKey;
        }
    }

    public LicenseAnalytics() {
        this.storagePath = Paths.get(System.getProperty("user.home"), ".licify", ANALYTICS_FILE);
        loadAnalytics();
    }

    public LicenseAnalytics(String customStoragePath) {
        this.storagePath = Paths.get(customStoragePath);
        loadAnalytics();
    }

    /**
     * Records a license activation event.
     *
     * @param licenseKey The license key being activated
     * @param hardwareId The hardware ID of the activating machine
     */
    public void recordActivation(String licenseKey, String hardwareId) {
        AnalyticsData data = getOrCreateAnalytics(licenseKey);
        data.activationCount++;
        if (data.firstActivationTime == 0) {
            data.firstActivationTime = System.currentTimeMillis();
        }
        data.lastValidationTime = System.currentTimeMillis();
        
        // Track hardware ID usage
        data.hardwareIdUsage.merge(hardwareId, 1, Integer::sum);
        
        // Add to history
        addHistoryEntry(data, "ACTIVATION", hardwareId);
        
        saveAnalytics();
    }

    /**
     * Records a license validation event.
     *
     * @param licenseKey The license key being validated
     * @param hardwareId The hardware ID of the validating machine
     * @param success Whether the validation was successful
     */
    public void recordValidation(String licenseKey, String hardwareId, boolean success) {
        AnalyticsData data = getOrCreateAnalytics(licenseKey);
        data.validationCount++;
        data.lastValidationTime = System.currentTimeMillis();
        
        // Track hardware ID usage
        data.hardwareIdUsage.merge(hardwareId, 1, Integer::sum);
        
        // Add to history
        String status = success ? "SUCCESS" : "FAILED";
        addHistoryEntry(data, "VALIDATION_" + status, hardwareId);
        
        saveAnalytics();
    }

    /**
     * Records a license deactivation event.
     *
     * @param licenseKey The license key being deactivated
     * @param hardwareId The hardware ID of the deactivating machine
     */
    public void recordDeactivation(String licenseKey, String hardwareId) {
        AnalyticsData data = getOrCreateAnalytics(licenseKey);
        data.deactivationCount++;
        
        // Track hardware ID usage
        if (data.hardwareIdUsage.containsKey(hardwareId)) {
            data.hardwareIdUsage.put(hardwareId, data.hardwareIdUsage.get(hardwareId) - 1);
            if (data.hardwareIdUsage.get(hardwareId) <= 0) {
                data.hardwareIdUsage.remove(hardwareId);
            }
        }
        
        // Add to history
        addHistoryEntry(data, "DEACTIVATION", hardwareId);
        
        saveAnalytics();
    }

    /**
     * Gets analytics data for a specific license.
     *
     * @param licenseKey The license key to query
     * @return AnalyticsData object or null if not found
     */
    public AnalyticsData getAnalytics(String licenseKey) {
        return analyticsMap.get(licenseKey);
    }

    /**
     * Gets all tracked license keys.
     *
     * @return Set of license keys
     */
    public Set<String> getAllLicenseKeys() {
        return new HashSet<>(analyticsMap.keySet());
    }

    /**
     * Generates a summary report of all license analytics.
     *
     * @return Formatted report string
     */
    public String generateReport() {
        StringBuilder report = new StringBuilder();
        report.append("=== LICENSE ANALYTICS REPORT ===\n");
        report.append("Generated: ").append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\n\n");

        for (Map.Entry<String, AnalyticsData> entry : analyticsMap.entrySet()) {
            AnalyticsData data = entry.getValue();
            report.append("License: ").append(data.licenseKey).append("\n");
            report.append("  Activations: ").append(data.activationCount).append("\n");
            report.append("  Validations: ").append(data.validationCount).append("\n");
            report.append("  Deactivations: ").append(data.deactivationCount).append("\n");
            report.append("  First Activation: ").append(new Date(data.firstActivationTime)).append("\n");
            report.append("  Last Validation: ").append(new Date(data.lastValidationTime)).append("\n");
            report.append("  Active Hardware IDs: ").append(data.hardwareIdUsage.size()).append("\n");
            
            if (!data.hardwareIdUsage.isEmpty()) {
                report.append("  Hardware Distribution:\n");
                for (Map.Entry<String, Integer> hw : data.hardwareIdUsage.entrySet()) {
                    report.append("    - ").append(hw.getKey()).append(": ").append(hw.getValue()).append(" uses\n");
                }
            }
            report.append("\n");
        }

        return report.toString();
    }

    /**
     * Exports analytics data to a JSON file.
     *
     * @param exportPath Path to export the JSON file
     * @throws IOException If export fails
     */
    public void exportToJson(String exportPath) throws IOException {
        StringBuilder json = new StringBuilder();
        json.append("{\n  \"licenses\": [\n");
        
        boolean first = true;
        for (AnalyticsData data : analyticsMap.values()) {
            if (!first) json.append(",\n");
            first = false;
            
            json.append("    {\n");
            json.append("      \"licenseKey\": \"").append(escapeJson(data.licenseKey)).append("\",\n");
            json.append("      \"activationCount\": ").append(data.activationCount).append(",\n");
            json.append("      \"validationCount\": ").append(data.validationCount).append(",\n");
            json.append("      \"deactivationCount\": ").append(data.deactivationCount).append(",\n");
            json.append("      \"firstActivationTime\": ").append(data.firstActivationTime).append(",\n");
            json.append("      \"lastValidationTime\": ").append(data.lastValidationTime).append(",\n");
            json.append("      \"hardwareIds\": {\n");
            
            boolean firstHw = true;
            for (Map.Entry<String, Integer> hw : data.hardwareIdUsage.entrySet()) {
                if (!firstHw) json.append(",\n");
                firstHw = false;
                json.append("        \"").append(escapeJson(hw.getKey())).append("\": ").append(hw.getValue());
            }
            
            json.append("\n      }\n");
            json.append("    }");
        }
        
        json.append("\n  ]\n}");
        
        Files.writeString(Paths.get(exportPath), json.toString());
    }

    private AnalyticsData getOrCreateAnalytics(String licenseKey) {
        return analyticsMap.computeIfAbsent(licenseKey, AnalyticsData::new);
    }

    private void addHistoryEntry(AnalyticsData data, String eventType, String hardwareId) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        String entry = String.format("[%s] %s on %s", timestamp, eventType, hardwareId);
        data.validationHistory.add(entry);
        
        // Keep only last 100 entries to prevent memory issues
        if (data.validationHistory.size() > 100) {
            data.validationHistory = data.validationHistory.subList(data.validationHistory.size() - 100, data.validationHistory.size());
        }
    }

    private void saveAnalytics() {
        try {
            // Create parent directories if they don't exist
            Files.createDirectories(storagePath.getParent());
            
            // Simple serialization (in production, use proper JSON library)
            StringBuilder data = new StringBuilder();
            for (AnalyticsData ad : analyticsMap.values()) {
                data.append(ad.licenseKey).append("|")
                    .append(ad.activationCount).append("|")
                    .append(ad.validationCount).append("|")
                    .append(ad.deactivationCount).append("|")
                    .append(ad.firstActivationTime).append("|")
                    .append(ad.lastValidationTime).append("\n");
            }
            
            Files.writeString(storagePath, data.toString());
        } catch (IOException e) {
            // Log error but don't fail silently in production
            System.err.println("Failed to save analytics: " + e.getMessage());
        }
    }

    private void loadAnalytics() {
        if (!Files.exists(storagePath)) {
            return;
        }
        
        try {
            List<String> lines = Files.readAllLines(storagePath);
            for (String line : lines) {
                String[] parts = line.split("\\|");
                if (parts.length >= 6) {
                    AnalyticsData data = new AnalyticsData(parts[0]);
                    data.activationCount = Integer.parseInt(parts[1]);
                    data.validationCount = Integer.parseInt(parts[2]);
                    data.deactivationCount = Integer.parseInt(parts[3]);
                    data.firstActivationTime = Long.parseLong(parts[4]);
                    data.lastValidationTime = Long.parseLong(parts[5]);
                    analyticsMap.put(parts[0], data);
                }
            }
        } catch (IOException e) {
            System.err.println("Failed to load analytics: " + e.getMessage());
        }
    }

    private String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }
}
