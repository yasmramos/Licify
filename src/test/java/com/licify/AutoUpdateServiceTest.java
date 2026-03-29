package com.licify;

import com.licify.core.AutoUpdateService;
import com.licify.core.AutoUpdateService.UpdateInfo;
import com.licify.core.AutoUpdateService.ProgressListener;
import org.junit.jupiter.api.*;
import java.nio.file.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AutoUpdateService.
 */
public class AutoUpdateServiceTest {
    
    private AutoUpdateService updateService;
    private Path testUpdateDir;
    
    @BeforeEach
    public void setUp() throws Exception {
        testUpdateDir = Files.createTempDirectory("updates-test");
        updateService = new AutoUpdateService("1.0.0", "https://example.com/api", testUpdateDir);
    }
    
    @AfterEach
    public void tearDown() throws Exception {
        if (testUpdateDir != null && Files.exists(testUpdateDir)) {
            deleteDirectory(testUpdateDir);
        }
    }
    
    @Test
    @DisplayName("Should initialize with correct version")
    public void testGetCurrentVersion() {
        assertEquals("1.0.0", updateService.getCurrentVersion());
    }
    
    @Test
    @DisplayName("Should compare versions correctly")
    public void testCompareVersions() {
        assertEquals(0, AutoUpdateService.compareVersions("1.0.0", "1.0.0"));
        assertTrue(AutoUpdateService.compareVersions("2.0.0", "1.0.0") > 0);
        assertTrue(AutoUpdateService.compareVersions("1.0.0", "2.0.0") < 0);
        assertTrue(AutoUpdateService.compareVersions("1.2.0", "1.0.0") > 0);
        assertTrue(AutoUpdateService.compareVersions("1.0.1", "1.0.0") > 0);
        assertTrue(AutoUpdateService.compareVersions("1.10.0", "1.9.0") > 0);
    }
    
    @Test
    @DisplayName("Should handle version strings with prefixes")
    public void testCompareVersionsWithPrefixes() {
        assertEquals(0, AutoUpdateService.compareVersions("v1.0.0", "1.0.0"));
        assertTrue(AutoUpdateService.compareVersions("v2.0.0", "v1.0.0") > 0);
        assertTrue(AutoUpdateService.compareVersions("release-1.0.0", "1.0.0") == 0);
    }
    
    @Test
    @DisplayName("Should create update directory if not exists")
    public void testUpdateDirectoryCreation() throws Exception {
        Path newDir = Files.createTempDirectory("updates-new").resolve("subdir");
        Files.deleteIfExists(newDir);
        
        AutoUpdateService service = new AutoUpdateService("1.0.0", 
                                                          "https://example.com/api", 
                                                          newDir);
        
        assertTrue(Files.exists(newDir));
        
        // Cleanup
        deleteDirectory(newDir.getParent());
    }
    
    @Test
    @DisplayName("Should verify checksum correctly")
    public void testVerifyChecksum() throws Exception {
        // Create a test file
        Path testFile = testUpdateDir.resolve("test.jar");
        String content = "test content";
        Files.writeString(testFile, content);
        
        // Calculate expected checksum manually (SHA-256 of "test content")
        String expectedChecksum = "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72";
        
        boolean valid = updateService.verifyChecksum(testFile, expectedChecksum);
        assertTrue(valid);
    }
    
    @Test
    @DisplayName("Should return false for invalid checksum")
    public void testVerifyChecksum_Invalid() throws Exception {
        Path testFile = testUpdateDir.resolve("test.jar");
        Files.writeString(testFile, "test content");
        
        boolean valid = updateService.verifyChecksum(testFile, "invalid-checksum");
        assertFalse(valid);
    }
    
    @Test
    @DisplayName("Should handle non-existent file in checksum verification")
    public void testVerifyChecksum_FileNotFound() {
        Path nonExistentFile = testUpdateDir.resolve("nonexistent.jar");
        boolean valid = updateService.verifyChecksum(nonExistentFile, "any-checksum");
        assertFalse(valid);
    }
    
    @Test
    @DisplayName("Should detect newer version")
    public void testIsNewerVersion() {
        AutoUpdateService service = new AutoUpdateService("1.0.0", 
                                                          "https://example.com/api");
        // Test indirectly through compareVersions
        assertTrue(AutoUpdateService.compareVersions("2.0.0", "1.0.0") > 0);
    }
    
    @Test
    @DisplayName("Should handle equal versions")
    public void testEqualVersions() {
        assertEquals(0, AutoUpdateService.compareVersions("1.0.0", "1.0.0"));
        assertEquals(0, AutoUpdateService.compareVersions("2.5.3", "2.5.3"));
    }
    
    @Test
    @DisplayName("Should handle multi-digit version numbers")
    public void testMultiDigitVersions() {
        assertTrue(AutoUpdateService.compareVersions("10.0.0", "9.0.0") > 0);
        assertTrue(AutoUpdateService.compareVersions("1.10.0", "1.9.0") > 0);
        assertTrue(AutoUpdateService.compareVersions("1.0.10", "1.0.9") > 0);
    }
    
    @Test
    @DisplayName("Should handle versions with different segment counts")
    public void testDifferentSegmentCounts() {
        assertTrue(AutoUpdateService.compareVersions("2.0", "1.9.9") > 0);
        assertTrue(AutoUpdateService.compareVersions("1.0.0.1", "1.0.0") > 0);
        assertEquals(0, AutoUpdateService.compareVersions("1.0", "1.0.0"));
    }
    
    @Test
    @DisplayName("Should create service with default update directory")
    public void testDefaultConstructor() {
        AutoUpdateService service = new AutoUpdateService("1.0.0", 
                                                          "https://example.com/api");
        assertNotNull(service);
        assertEquals("1.0.0", service.getCurrentVersion());
    }
    
    @Test
    @DisplayName("Should handle URL with trailing slash")
    public void testUrlWithTrailingSlash() {
        AutoUpdateService service1 = new AutoUpdateService("1.0.0", 
                                                           "https://example.com/api/");
        AutoUpdateService service2 = new AutoUpdateService("1.0.0", 
                                                           "https://example.com/api");
        
        assertNotNull(service1);
        assertNotNull(service2);
    }
    
    private void deleteDirectory(Path dir) throws Exception {
        if (!Files.exists(dir)) return;
        
        Files.walk(dir)
            .sorted((a, b) -> b.compareTo(a))
            .forEach(path -> {
                try {
                    Files.delete(path);
                } catch (Exception e) {
                    // Ignore
                }
            });
    }
}
