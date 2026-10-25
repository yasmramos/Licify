package com.licify.integration;

import com.licify.Licify;
import com.licify.Licify.License;
import com.licify.core.LicenseRevocationManager;
import com.licify.encryption.EncryptionConfig;
import com.licify.io.IOFormat;
import com.licify.signing.SignatureConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end test covering the complete license lifecycle exactly the way an
 * integrator would use it: key generation -> license creation -> signing ->
 * persistence in every IO format -> verification -> revocation -> tamper
 * detection -> encrypted storage round-trips.
 *
 * <p>Unlike the unit tests, this class exercises several subsystems together
 * (signing, hardware binding, serialization, encryption and revocation) to
 * catch integration regressions that isolated tests cannot see.</p>
 */
@DisplayName("E2E: full license lifecycle")
class LicenseLifecycleE2EIT {

    @TempDir
    Path tempDir;

    private KeyPair issuerKeyPair;
    private PublicKey attackerPublicKey;

    @BeforeEach
    void setUp() throws Exception {
        issuerKeyPair = Licify.generateKeyPair();
        // A completely unrelated key pair used to simulate a rogue issuer.
        attackerPublicKey = Licify.generateKeyPair().getPublic();
        Licify.setDefaultSignatureConfig(new SignatureConfig());
        Licify.setDefaultEncryptionConfig(new EncryptionConfig());
        LicenseRevocationManager.getInstance().clearAllRevocations();
    }

    @AfterEach
    void tearDown() {
        LicenseRevocationManager.getInstance().clearAllRevocations();
    }

    private License buildSignedLicense(String licenseeName) throws Exception {
        Set<String> features = new LinkedHashSet<>();
        features.add("export");
        features.add("analytics");

        License license = Licify.license()
                .licenseeName(licenseeName)
                .licenseeEmail(licenseeName.toLowerCase().replace(' ', '.') + "@example.com")
                .productId("licify-demo-app")
                .productVersion("0.1.0")
                .expirationDate(LocalDateTime.now().plusDays(30))
                .maxUsers(5)
                .features(features)
                .customData("order-42")
                .hardwareId(Licify.getHardwareId())
                .build();

        return Licify.sign(license, issuerKeyPair);
    }

    @Test
    @DisplayName("issue -> sign -> verify succeeds for a genuine license on this machine")
    void issueSignAndVerifyHappyPath() throws Exception {
        License signed = buildSignedLicense("Acme Corp");

        assertNotNull(signed.getSignature(), "signing must attach a signature");
        assertEquals("SHA256withRSA", signed.getSignatureAlgorithm());
        assertNotNull(signed.getPublicKeyFingerprint(), "fingerprint must be bound at signing time");
        assertFalse(Licify.isRevoke(signed));

        assertTrue(Licify.verify(signed, issuerKeyPair.getPublic()),
                "a freshly signed license must pass end-to-end verification");
        assertTrue(Licify.isValidLicense(signed));
    }

    @Test
    @DisplayName("verification fails when the wrong public key is supplied")
    void verifyRejectsForeignPublicKey() throws Exception {
        License signed = buildSignedLicense("Beta LLC");

        assertFalse(Licify.verify(signed, attackerPublicKey),
                "a license signed by another issuer must never verify");
    }

    @Test
    @DisplayName("tampering with any signed field invalidates the signature")
    void tamperDetectionBreaksVerification() throws Exception {
        License signed = buildSignedLicense("Gamma Inc");
        String originalSignature = signed.getSignature();

        signed.setLicenseeName("Evil Corp");
        assertFalse(Licify.verify(signed, issuerKeyPair.getPublic()),
                "modifying the licensee name must break verification");

        // Restore identity, then attack the expiration date instead.
        signed.setLicenseeName("Gamma Inc");
        signed.setSignature(originalSignature);
        signed.setExpirationDate(LocalDateTime.now().plusYears(10));
        assertFalse(Licify.verify(signed, issuerKeyPair.getPublic()),
                "extending the expiration date must break verification");
    }

    @Test
    @DisplayName("revocation works by license key across save/load boundaries")
    void revocationSurvivesRoundTrip() throws Exception {
        License signed = buildSignedLicense("Delta Ltd");
        Path file = tempDir.resolve("delta.bin");

        Licify.save(signed, file.toString(), IOFormat.BINARY);
        License reloaded = Licify.load(file.toString(), IOFormat.BINARY);

        assertEquals(signed.getLicenseKey(), reloaded.getLicenseKey());
        assertFalse(Licify.isRevoke(reloaded));

        Licify.revoke(signed);

        assertTrue(Licify.isRevoke(reloaded),
                "a reloaded instance sharing the same key must be reported as revoked");
        assertTrue(LicenseRevocationManager.getInstance()
                .getRevokedLicenses().contains(signed.getLicenseKey()));
    }

    @Test
    @DisplayName("revoking a license without a key is rejected explicitly")
    void revokeRequiresLicenseKey() {
        License anonymous = new License();
        assertThrows(IllegalArgumentException.class, () -> Licify.revoke(anonymous));
        assertFalse(Licify.isRevoke(anonymous));
        assertFalse(Licify.isRevoke(null));
    }

    @Test
    @DisplayName("STRING format round-trip preserves signature material and verifies again")
    void stringFormatRoundTripKeepsVerifiability() throws Exception {
        License signed = buildSignedLicense("Epsilon GmbH");
        Path file = tempDir.resolve("epsilon.txt");

        Licify.save(signed, file.toString(), IOFormat.STRING);
        License reloaded = Licify.load(file.toString(), IOFormat.STRING);

        assertEquals(signed.getLicenseKey(), reloaded.getLicenseKey());
        assertEquals(signed.getSignature(), reloaded.getSignature());
        assertEquals(signed.getSignatureAlgorithm(), reloaded.getSignatureAlgorithm());
        assertEquals(signed.getPublicKeyFingerprint(), reloaded.getPublicKeyFingerprint());
        assertEquals(signed.getHardwareId(), reloaded.getHardwareId());
        assertEquals(Set.of("export", "analytics"), reloaded.getFeatures());

        assertTrue(Licify.verify(reloaded, issuerKeyPair.getPublic()),
                "a text-serialized license must remain verifiable after reload");
    }

    @Test
    @DisplayName("BASE64 format round-trip preserves all fields")
    void base64FormatRoundTrip() throws Exception {
        License signed = buildSignedLicense("Zeta SA");
        Path file = tempDir.resolve("zeta.b64");

        Licify.save(signed, file.toString(), IOFormat.BASE64);
        License reloaded = Licify.load(file.toString(), IOFormat.BASE64);

        assertEquals(signed.getLicenseKey(), reloaded.getLicenseKey());
        assertEquals(signed.getSignature(), reloaded.getSignature());
        assertEquals("Zeta SA", reloaded.getLicenseeName());
        assertTrue(Licify.verify(reloaded, issuerKeyPair.getPublic()));
    }

    @Test
    @DisplayName("encrypted persistence round-trip keeps signature validity")
    void encryptedRoundTripKeepsVerifiability() throws Exception {
        License signed = buildSignedLicense("Eta Industries");
        Path file = tempDir.resolve("eta.enc");

        PrivateKey privateKey = issuerKeyPair.getPrivate();
        PublicKey publicKey = issuerKeyPair.getPublic();

        Licify.saveEncryptedLicense(signed, file.toString(), publicKey);
        License decrypted = Licify.loadEncryptedLicense(file.toString(), privateKey);

        assertEquals(signed.getLicenseKey(), decrypted.getLicenseKey());
        assertEquals(signed.getSignature(), decrypted.getSignature());
        assertTrue(Licify.verify(decrypted, publicKey),
                "decrypting a license must not alter its signed content");
    }

    @Test
    @DisplayName("corrupted license text produces a clear error, not silent data loss")
    void corruptedTextFailsWithContext() {
        String broken = "version=1.0\nissueDate=not-a-date\nlicenseKey=ABC";

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> Licify.createLicenseFromText(broken));
        assertTrue(ex.getMessage().contains("issueDate"),
                "error message should identify the corrupted field");
    }

    @Test
    @DisplayName("empty or null license text parses to null instead of throwing")
    void blankLicenseTextYieldsNull() {
        assertNull(Licify.createLicenseFromText(null));
        assertNull(Licify.createLicenseFromText("   "));
    }

    @Test
    @DisplayName("build() propagates persistence failures instead of hiding them")
    void buildPropagatesSaveFailure() {
        String invalidPath = tempDir.resolve("file.bin").toString() + "/nested/invalid";

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> Licify.license()
                        .licenseeName("Theta Co")
                        .expirationDate(LocalDateTime.now().plusDays(1))
                        .file(invalidPath)
                        .build());
        assertTrue(ex.getMessage().contains("Failed to save license"));
    }

    @Test
    @DisplayName("trial helper creates an expiring, marked-as-trial license")
    void trialLicenseHelperEndToEnd() throws Exception {
        License trial = Licify.createTrialLicense("Winston", "winston@example.com",
                "licify-demo-app", "0.1.0", 7);
        assertNotNull(trial.getLicenseKey());
        assertTrue(trial.isTrial());
        assertEquals("TRIAL", trial.getLicenseType());
        assertNotNull(trial.getExpirationDate());
        assertTrue(trial.getExpirationDate().isAfter(LocalDateTime.now()));
        assertFalse(trial.isExpired());

        License signedTrial = Licify.sign(trial, issuerKeyPair);
        assertTrue(Licify.verify(signedTrial, issuerKeyPair.getPublic()));
    }

    @Test
    @DisplayName("expired licenses fail business validation even with a valid signature")
    void expiredLicenseIsRejected() throws Exception {
        License expired = Licify.license()
                .licenseeName("Kappa Ltd")
                .expirationDate(LocalDateTime.now().minusDays(1))
                .hardwareId(Licify.getHardwareId())
                .build();
        Licify.sign(expired, issuerKeyPair);

        assertTrue(expired.isExpired());
        assertFalse(Licify.isValidLicense(expired),
                "an expired license must not pass basic validation");
    }

    @Test
    @DisplayName("debug helper runs without exceptions on a genuine license")
    void debugVerificationDoesNotThrow() throws Exception {
        License signed = buildSignedLicense("Lambda AG");
        assertDoesNotThrow(() ->
                Licify.debugSignatureVerification(signed, issuerKeyPair.getPublic()));
    }
}
