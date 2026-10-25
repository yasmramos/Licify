package com.licify.integration;

import com.licify.Licify;
import com.licify.Licify.License;
import com.licify.analytics.LicenseAnalytics;
import com.licify.core.FloatingLicenseManager;
import com.licify.core.LicenseRevocationManager;
import com.licify.encryption.EncryptionConfig;
import com.licify.io.IOFormat;
import com.licify.offline.OfflineActivationService;
import com.licify.security.TamperDetection;
import com.licify.signing.SignatureConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.KeyPair;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests that wire multiple Licify subsystems together (floating
 * sessions, offline activation, analytics and tamper detection) on top of the
 * core signing/verification pipeline, using real files in temporary
 * directories rather than mocks.
 */
@DisplayName("Integration: cross-subsystem workflows")
class CrossSubsystemWorkflowIT {

    @TempDir
    Path tempDir;

    private KeyPair issuerKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        issuerKeyPair = Licify.generateKeyPair();
        Licify.setDefaultSignatureConfig(new SignatureConfig());
        Licify.setDefaultEncryptionConfig(new EncryptionConfig());
        LicenseRevocationManager.getInstance().clearAllRevocations();
    }

    private License signedFloatingLicense(int maxUsers) throws Exception {
        License license = Licify.commercialLicense()
                .licenseeName("Floating Customer")
                .productId("licify-demo-app")
                .productVersion("0.1.0")
                .expirationDate(LocalDateTime.now().plusDays(90))
                .maxUsers(maxUsers)
                .hardwareId(Licify.getHardwareId())
                .build();
        return Licify.sign(license, issuerKeyPair);
    }

    @Test
    @DisplayName("floating sessions enforce seat limits and survive a manager restart")
    void floatingSeatLimitAndPersistenceAcrossRestart() {
        Path sessionFile = tempDir.resolve("sessions.json");
        FloatingLicenseManager manager = new FloatingLicenseManager(sessionFile);

        String licenseId = "FLOAT-SEAT-LIMIT";
        FloatingLicenseManager.ActivationResult first =
                manager.activateSession(licenseId, "client-1", "host-a", 2);
        FloatingLicenseManager.ActivationResult second =
                manager.activateSession(licenseId, "client-2", "host-b", 2);
        assertTrue(first.isSuccess());
        assertTrue(second.isSuccess());
        assertEquals(2, manager.getActiveSessionCount(licenseId));
        assertEquals(0, manager.getAvailableSlots(licenseId, 2));

        // Third client must be rejected: the seat limit is exhausted.
        FloatingLicenseManager.ActivationResult third =
                manager.activateSession(licenseId, "client-3", "host-c", 2);
        assertFalse(third.isSuccess(), "seat limit must reject the third concurrent user");
        assertTrue(third.getMessage().contains("limit"));

        // Simulate an application restart: a brand-new manager instance must
        // recover exactly the persisted active sessions from disk. The
        // constructor already reloads the session store, so no explicit load
        // call is needed here.
        FloatingLicenseManager restarted = new FloatingLicenseManager(sessionFile);
        assertEquals(2, restarted.getActiveSessionCount(licenseId),
                "sessions must round-trip through the JSON store unchanged");

        // Freeing a slot lets the waiting client connect.
        assertTrue(restarted.deactivateSession(first.getSessionId()));
        FloatingLicenseManager.ActivationResult retry =
                restarted.activateSession(licenseId, "client-3", "host-c", 2);
        assertTrue(retry.isSuccess(), "a released seat must become available again");
    }

    @Test
    @DisplayName("heartbeat updates keep sessions alive and expired ones are cleaned up")
    void heartbeatKeepsSessionAliveWhileExpiredOnesAreRemoved() throws Exception {
        Path sessionFile = tempDir.resolve("hb-sessions.json");
        FloatingLicenseManager manager = new FloatingLicenseManager(sessionFile);

        FloatingLicenseManager.ActivationResult result =
                manager.activateSession("FLOAT-HB", "client-1", "host-a", 1);
        String sessionId = result.getSessionId();
        assertNotNull(sessionId);

        assertTrue(manager.updateHeartbeat(sessionId));
        assertFalse(manager.updateHeartbeat("unknown-session-id"),
                "heartbeats for unknown sessions must be reported as failures");

        // A zero-minute timeout treats every session as stale.
        int cleaned = manager.cleanupExpiredSessions(0);
        assertEquals(1, cleaned);
        assertEquals(0, manager.getActiveSessionCount("FLOAT-HB"));
        assertFalse(Path.of(sessionFile.toString()).toFile().exists()
                        && manager.getAllActiveSessions().size() > 0);
    }

    @Test
    @DisplayName("offline activation request/response round-trip validates against admin key")
    void offlineActivationRoundTrip() throws Exception {
        KeyPair adminKeyPair = Licify.generateKeyPair();
        OfflineActivationService service = new OfflineActivationService(adminKeyPair);

        License license = signedFloatingLicense(1);
        String fingerprint = Licify.getHardwareId();

        String request = service.generateActivationRequest(license, fingerprint);
        assertNotNull(request);

        Path requestFile = tempDir.resolve("activation.req");
        service.saveActivationRequest(request, requestFile.toString());
        String loaded = service.loadActivationRequest(requestFile.toString());
        assertEquals(request, loaded, "request file content must match what was saved");

        // The administrator approves the request by re-signing its payload.
        byte[] decoded = java.util.Base64.getDecoder().decode(request);
        String payload = new String(decoded).split("::")[0];
        String response = java.util.Base64.getEncoder().encodeToString(
                (payload + "::" + com.licify.signing.DigitalSignature.signSHA512(
                        payload, adminKeyPair.getPrivate())).getBytes());

        String token = service.processActivationResponse(response);
        assertTrue(token.startsWith("Activation Successful. Token:"),
                "a correctly signed response must produce an activation token");
    }

    @Test
    @DisplayName("offline activation rejects responses signed with a foreign key")
    void offlineActivationRejectsForgedResponse() throws Exception {
        KeyPair adminKeyPair = Licify.generateKeyPair();
        OfflineActivationService service = new OfflineActivationService(adminKeyPair);

        License license = signedFloatingLicense(1);
        String request = service.generateActivationRequest(license, Licify.getHardwareId());
        String payload = new String(java.util.Base64.getDecoder().decode(request)).split("::")[0];

        // Rogue attacker signs the same payload with their own key.
        KeyPair rogueKeyPair = Licify.generateKeyPair();
        String forged = java.util.Base64.getEncoder().encodeToString(
                (payload + "::" + com.licify.signing.DigitalSignature.signSHA512(
                        payload, rogueKeyPair.getPrivate())).getBytes());

        assertThrows(SecurityException.class,
                () -> service.processActivationResponse(forged),
                "responses not signed by the admin key must be rejected");
    }

    @Test
    @DisplayName("analytics tracks activations, validations and deactivations for a real license")
    void analyticsRecordsFullUsageJourney() throws Exception {
        Path analyticsFile = tempDir.resolve("analytics.json");
        LicenseAnalytics analytics = new LicenseAnalytics(analyticsFile.toString());

        License license = signedFloatingLicense(3);
        String key = license.getLicenseKey();
        String hw = Licify.getHardwareId();

        analytics.recordActivation(key, hw);
        analytics.recordValidation(key, hw, true);
        analytics.recordValidation(key, hw, false);
        analytics.recordDeactivation(key, hw);

        LicenseAnalytics.AnalyticsData data = analytics.getAnalytics(key);
        assertEquals(1, data.activationCount);
        assertEquals(2, data.validationCount);
        assertEquals(1, data.deactivationCount);
        assertTrue(data.hardwareIdUsage.containsKey(hw));
        assertTrue(analytics.getAllLicenseKeys().contains(key));
        assertNotNull(analytics.generateReport());

        // Export and reload to prove persistence integrity across instances.
        Path exported = tempDir.resolve("exported-analytics.json");
        analytics.exportToJson(exported.toString());
        LicenseAnalytics reloaded = new LicenseAnalytics(exported.toString());
        assertEquals(2, reloaded.getAnalytics(key).validationCount,
                "reloaded analytics must match what was recorded before export");
    }

    @Test
    @DisplayName("checksum-based integrity check detects modified license payloads")
    void tamperDetectionCatchesModifiedPayload() throws Exception {
        License license = signedFloatingLicense(1);
        String canonical = Licify.serializeLicenseWithMetadata(license);

        String checksum = TamperDetection.generateChecksum(canonical);
        assertTrue(TamperDetection.validateDataIntegrity(canonical, checksum),
                "untouched payload must pass integrity validation");

        String tampered = canonical.replace(
                "expirationDate=" + license.getExpirationDate(),
                "expirationDate=" + LocalDateTime.now().plusYears(5));
        assertFalse(TamperDetection.validateDataIntegrity(tampered, checksum),
                "a modified expiration date must fail integrity validation");
    }

    @Test
    @DisplayName("revoked license still verifies cryptographically but is blocked at business level")
    void revokedLicenseIsBlockedDespiteValidSignature() throws Exception {
        License license = signedFloatingLicense(1);

        // Cryptographic verification remains valid: revocation is a separate,
        // authoritative layer checked via the revocation list.
        assertTrue(Licify.verify(license, issuerKeyPair.getPublic()));

        Licify.revoke(license);
        assertTrue(Licify.isRevoke(license));
        assertFalse(Licify.isRevoke(null));

        // A copy sharing the same key (e.g. loaded from disk) is also blocked.
        Path file = tempDir.resolve("revoked-copy.bin");
        Licify.save(license, file.toString(), IOFormat.BINARY);
        License copy = Licify.load(file.toString(), IOFormat.BINARY);
        assertTrue(Licify.isRevoke(copy),
                "revocation must apply to any instance carrying the revoked key");
    }
}
