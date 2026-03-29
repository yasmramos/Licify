package com.licify.analytics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for LicenseAnalytics class.
 */
class LicenseAnalyticsTest {

    private LicenseAnalytics analytics;
    
    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        Path customPath = tempDir.resolve("test_analytics.dat");
        analytics = new LicenseAnalytics(customPath.toString());
    }

    @Test
    void testRecordActivation() {
        String licenseKey = "TEST-LICENSE-001";
        String hardwareId = "HWID-ABC-123";
        
        analytics.recordActivation(licenseKey, hardwareId);
        
        LicenseAnalytics.AnalyticsData data = analytics.getAnalytics(licenseKey);
        assertNotNull(data);
        assertEquals(1, data.activationCount);
        assertEquals(0, data.validationCount);
        assertEquals(0, data.deactivationCount);
        assertTrue(data.firstActivationTime > 0);
        assertTrue(data.lastValidationTime > 0);
        assertEquals(1, data.hardwareIdUsage.size());
        assertEquals(1, data.hardwareIdUsage.get(hardwareId));
    }

    @Test
    void testRecordMultipleActivations() {
        String licenseKey = "TEST-LICENSE-002";
        String hardwareId1 = "HWID-ABC-123";
        String hardwareId2 = "HWID-DEF-456";
        
        analytics.recordActivation(licenseKey, hardwareId1);
        analytics.recordActivation(licenseKey, hardwareId1);
        analytics.recordActivation(licenseKey, hardwareId2);
        
        LicenseAnalytics.AnalyticsData data = analytics.getAnalytics(licenseKey);
        assertNotNull(data);
        assertEquals(3, data.activationCount);
        assertEquals(2, data.hardwareIdUsage.size());
        assertEquals(2, data.hardwareIdUsage.get(hardwareId1));
        assertEquals(1, data.hardwareIdUsage.get(hardwareId2));
    }

    @Test
    void testRecordValidation() {
        String licenseKey = "TEST-LICENSE-003";
        String hardwareId = "HWID-GHI-789";
        
        analytics.recordValidation(licenseKey, hardwareId, true);
        analytics.recordValidation(licenseKey, hardwareId, false);
        
        LicenseAnalytics.AnalyticsData data = analytics.getAnalytics(licenseKey);
        assertNotNull(data);
        assertEquals(2, data.validationCount);
        assertEquals(1, data.hardwareIdUsage.get(hardwareId));
        
        // Check history contains both success and failure
        assertTrue(data.validationHistory.stream().anyMatch(h -> h.contains("SUCCESS")));
        assertTrue(data.validationHistory.stream().anyMatch(h -> h.contains("FAILED")));
    }

    @Test
    void testRecordDeactivation() {
        String licenseKey = "TEST-LICENSE-004";
        String hardwareId = "HWID-JKL-012";
        
        // Activate first
        analytics.recordActivation(licenseKey, hardwareId);
        analytics.recordActivation(licenseKey, hardwareId);
        
        // Then deactivate
        analytics.recordDeactivation(licenseKey, hardwareId);
        
        LicenseAnalytics.AnalyticsData data = analytics.getAnalytics(licenseKey);
        assertNotNull(data);
        assertEquals(2, data.activationCount);
        assertEquals(1, data.deactivationCount);
        assertEquals(1, data.hardwareIdUsage.get(hardwareId)); // Should still have 1 active
        
        // Deactivate again
        analytics.recordDeactivation(licenseKey, hardwareId);
        data = analytics.getAnalytics(licenseKey);
        assertNull(data.hardwareIdUsage.get(hardwareId)); // Should be removed
    }

    @Test
    void testGetAllLicenseKeys() {
        analytics.recordActivation("LICENSE-A", "HWID-A");
        analytics.recordActivation("LICENSE-B", "HWID-B");
        analytics.recordActivation("LICENSE-C", "HWID-C");
        
        Set<String> keys = analytics.getAllLicenseKeys();
        assertNotNull(keys);
        assertEquals(3, keys.size());
        assertTrue(keys.contains("LICENSE-A"));
        assertTrue(keys.contains("LICENSE-B"));
        assertTrue(keys.contains("LICENSE-C"));
    }

    @Test
    void testGenerateReport() {
        String licenseKey = "TEST-LICENSE-REPORT";
        analytics.recordActivation(licenseKey, "HWID-REPORT-1");
        analytics.recordValidation(licenseKey, "HWID-REPORT-1", true);
        
        String report = analytics.generateReport();
        assertNotNull(report);
        assertTrue(report.contains("LICENSE ANALYTICS REPORT"));
        assertTrue(report.contains(licenseKey));
        assertTrue(report.contains("Activations: 1"));
        assertTrue(report.contains("Validations: 1"));
    }

    @Test
    void testExportToJson(@TempDir Path exportDir) throws IOException {
        String licenseKey = "TEST-LICENSE-JSON";
        analytics.recordActivation(licenseKey, "HWID-JSON-1");
        analytics.recordActivation(licenseKey, "HWID-JSON-2");
        analytics.recordValidation(licenseKey, "HWID-JSON-1", true);
        
        Path exportPath = exportDir.resolve("analytics_export.json");
        analytics.exportToJson(exportPath.toString());
        
        assertTrue(Files.exists(exportPath));
        String jsonContent = Files.readString(exportPath);
        assertTrue(jsonContent.contains("\"licenseKey\": \"TEST-LICENSE-JSON\""));
        assertTrue(jsonContent.contains("\"activationCount\": 2"));
        assertTrue(jsonContent.contains("\"validationCount\": 1"));
    }

    @Test
    void testPersistenceAcrossInstances() {
        String licenseKey = "TEST-LICENSE-PERSIST";
        String hardwareId = "HWID-PERSIST-1";
        
        // Record some data
        analytics.recordActivation(licenseKey, hardwareId);
        analytics.recordValidation(licenseKey, hardwareId, true);
        
        // Create new instance with same storage path
        LicenseAnalytics analytics2 = new LicenseAnalytics(
            tempDir.resolve("test_analytics.dat").toString()
        );
        
        LicenseAnalytics.AnalyticsData data = analytics2.getAnalytics(licenseKey);
        assertNotNull(data);
        assertEquals(1, data.activationCount);
        assertEquals(1, data.validationCount);
    }

    @Test
    void testHistoryLimit() {
        String licenseKey = "TEST-LICENSE-HISTORY";
        String hardwareId = "HWID-HISTORY-1";
        
        // Record more than 100 validations
        for (int i = 0; i < 150; i++) {
            analytics.recordValidation(licenseKey, hardwareId, true);
        }
        
        LicenseAnalytics.AnalyticsData data = analytics.getAnalytics(licenseKey);
        assertNotNull(data);
        assertEquals(150, data.validationCount);
        assertTrue(data.validationHistory.size() <= 100); // Should be limited to 100
    }

    @Test
    void testGetAnalyticsForNonExistentLicense() {
        LicenseAnalytics.AnalyticsData data = analytics.getAnalytics("NON-EXISTENT");
        assertNull(data);
    }
}
