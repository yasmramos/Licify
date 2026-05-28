package com.licify.offline;

import com.licify.Licify;
import com.licify.Licify.License;
import com.licify.Licify.LicenseBuilder;
import com.licify.signing.DigitalSignature;
import com.licify.LicenseKeyPair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for OfflineActivationService.
 */
class OfflineActivationServiceTest {

    private OfflineActivationService service;
    
    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        service = new OfflineActivationService();
    }

    @Test
    void testGenerateActivationRequest() throws Exception {
        License license = new LicenseBuilder()
                .licenseeName("Test User")
                .expirationDate(LocalDateTime.now().plusDays(1))
                .build();
        license.setLicenseKey("TEST-KEY-123");

        String fingerprint = "HWID-ABC-123-XYZ";
        
        String request = service.generateActivationRequest(license, fingerprint);
        
        assertNotNull(request);
        assertFalse(request.isEmpty());
        // Should be Base64 encoded
        assertDoesNotThrow(() -> Base64.getDecoder().decode(request));
    }

    @Test
    void testGenerateActivationRequestWithNullLicense() {
        assertThrows(IllegalArgumentException.class, () -> 
            service.generateActivationRequest(null, "fingerprint")
        );
    }

    @Test
    void testGenerateActivationRequestWithNullFingerprint() throws Exception {
        License license = new LicenseBuilder()
                .licenseeName("Test User")
                .build();
        license.setLicenseKey("TEST-KEY-123");
        
        assertThrows(IllegalArgumentException.class, () -> 
            service.generateActivationRequest(license, null)
        );
    }

    @Test
    void testSaveAndLoadActivationRequest() throws Exception {
        License license = new LicenseBuilder()
                .licenseeName("Another User")
                .build();
        license.setLicenseKey("TEST-KEY-456");

        String fingerprint = "HWID-DEF-456-UVW";
        String request = service.generateActivationRequest(license, fingerprint);
        
        Path requestFile = tempDir.resolve("activation_request.txt");
        service.saveActivationRequest(request, requestFile.toString());
        
        assertTrue(Files.exists(requestFile));
        String loadedRequest = service.loadActivationRequest(requestFile.toString());
        
        assertEquals(request, loadedRequest);
    }

    @Test
    void testProcessActivationResponse() throws Exception {
        // First generate a valid request
        License license = new LicenseBuilder()
                .licenseeName("Third User")
                .build();
        license.setLicenseKey("TEST-KEY-789");
        
        String fingerprint = "HWID-GHI-789-RST";
        String request = service.generateActivationRequest(license, fingerprint);
        
        // In a real scenario, the administrator would process this and send back a signed response
        // For testing, we use the admin key pair from the service to sign the response
        java.security.KeyPair adminKp = LicenseKeyPair.generateRSAKeys(2048);
        String rawData = license.getLicenseKey() + "|" + fingerprint + "|" + System.currentTimeMillis();
        String signature = DigitalSignature.signSHA512(rawData, adminKp.getPrivate());
        String response = Base64.getEncoder().encodeToString((rawData + "::" + signature).getBytes());
        
        // Create a new service with the same key pair to verify
        OfflineActivationService verifyingService = new OfflineActivationService(adminKp);
        String result = verifyingService.processActivationResponse(response);
        
        assertNotNull(result);
        assertTrue(result.contains("Activation Successful"));
        assertTrue(result.contains("Token:"));
    }

    @Test
    void testProcessActivationResponseWithInvalidFormat() {
        String invalidResponse = Base64.getEncoder().encodeToString("invalid::format::too::many::parts".getBytes());
        
        assertThrows(IllegalArgumentException.class, () -> 
            service.processActivationResponse(invalidResponse)
        );
    }

    @Test
    void testProcessActivationResponseWithTamperedData() throws Exception {
        // Generate valid request
        License license = new LicenseBuilder()
                .licenseeName("Tamper Test")
                .build();
        license.setLicenseKey("TEST-KEY-TAMPER");
        
        String fingerprint = "HWID-TAMPER-123";
        String request = service.generateActivationRequest(license, fingerprint);
        
        // Decode and tamper with the data
        byte[] decodedBytes = Base64.getDecoder().decode(request);
        String decodedString = new String(decodedBytes);
        String[] parts = decodedString.split("::");
        
        // Tamper with the data part
        String tamperedData = "TAMPERED-DATA|" + fingerprint + "|" + System.currentTimeMillis();
        String tamperedResponse = Base64.getEncoder().encodeToString((tamperedData + "::" + parts[1]).getBytes());
        
        assertThrows(SecurityException.class, () -> 
            service.processActivationResponse(tamperedResponse)
        );
    }

    @Test
    void testLoadActivationRequestFromFileNotFound() {
        assertThrows(Exception.class, () -> 
            service.loadActivationRequest("/nonexistent/path/request.txt")
        );
    }

    @Test
    void testEndToEndOfflineActivation() throws Exception {
        // Step 1: Generate activation request
        License license = new LicenseBuilder()
                .licenseeName("End to End User")
                .expirationDate(LocalDateTime.now().plusDays(1))
                .build();
        license.setLicenseKey("E2E-KEY-999");

        String fingerprint = "HWID-E2E-FINAL";
        String request = service.generateActivationRequest(license, fingerprint);
        
        // Step 2: Save request to file
        Path requestFile = tempDir.resolve("e2e_request.txt");
        service.saveActivationRequest(request, requestFile.toString());
        
        // Step 3: Load request (simulating sending to admin)
        String loadedRequest = service.loadActivationRequest(requestFile.toString());
        assertEquals(request, loadedRequest);
        
        // Step 4: Admin processes and creates response (simulated)
        String[] requestParts = new String(Base64.getDecoder().decode(loadedRequest)).split("::");
        String adminResponseData = requestParts[0] + "|PROCESSED";
        
        // Use the same admin key pair that the service has
        java.security.KeyPair adminKp = LicenseKeyPair.generateRSAKeys(2048);
        OfflineActivationService verifyingService = new OfflineActivationService(adminKp);
        String adminSignature = DigitalSignature.signSHA512(adminResponseData, adminKp.getPrivate());
        String adminResponse = Base64.getEncoder().encodeToString((adminResponseData + "::" + adminSignature).getBytes());
        
        // Step 5: Process response
        String result = verifyingService.processActivationResponse(adminResponse);
        
        assertTrue(result.contains("Activation Successful"));
    }
}
