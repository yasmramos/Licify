package com.licify;

import com.licify.Licify.License;
import com.licify.encryption.EncryptionConfig;
import com.licify.signing.SignatureConfig;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests covering API surface that LicifyTest does not exercise:
 * License.Builder (legacy subclass with Date helpers), License feature
 * management, defensive-copy defaults and the nested License DTO behaviour.
 */
class LicifyApiTest {

    // ------------------------------------------------------------------
    // License.Builder (nested legacy builder extending LicenseBuilder)
    // ------------------------------------------------------------------

    @Test
    void licenseBuilderAppliesDefaultsOnBuild() {
        License license = new License.Builder("KEY-123", "Acme Corp").build();

        assertEquals("KEY-123", license.getLicenseKey());
        assertEquals("Acme Corp", license.getLicenseeName());
        assertEquals("COMMERCIAL", license.getLicenseType(), "build() applies the default license type");
        assertEquals("1.0", license.getVersion());
    }

    @Test
    void licenseBuilderDateHelpersConvertToDateTime() {
        Date issue = new Date(1_700_000_000_000L);
        Date expiration = new Date(1_800_000_000_000L);

        License license = new License.Builder("K", "Licensee")
                .setIssueDate(issue)
                .setExpirationDate(expiration)
                .build();

        assertNotNull(license.getIssueDate());
        assertNotNull(license.getExpirationDate());
        assertTrue(license.getExpirationDate().isAfter(license.getIssueDate()));
    }

    @Test
    void licenseBuilderDateHelpersIgnoreNullValues() {
        License license = new License.Builder("K", "Licensee")
                .setIssueDate(null)
                .setExpirationDate(null)
                .build();
        // build() must still fill a default issue date.
        assertNotNull(license.getIssueDate());
    }

    @Test
    void fluentBuilderGeneratesKeyAndDefaultsWhenMissing() {
        License license = Licify.license()
                .licenseeName("Jane Doe")
                .licenseeEmail("jane@example.com")
                .productId("widget")
                .productVersion("1.0.0")
                .maxUsers(5)
                .trial(false)
                .customData("order-42")
                .licenseType("STANDARD")
                .build();

        assertNotNull(license.getLicenseKey(), "build() generates an id when none provided");
        assertEquals("STANDARD", license.getLicenseType());
        assertEquals("Jane Doe", license.getLicenseeName());
        assertEquals(5, license.getMaxUsers());
        assertNotNull(license.getHardwareId());
    }

    @Test
    void fluentBuilderFeatureMethodsAddRemoveAndClear() {
        Set<String> initial = new LinkedHashSet<>();
        initial.add("export");
        initial.add("analytics");

        License license = Licify.license()
                .licenseeName("Features Inc")
                .features(initial)
                .feature("priority-support")
                .removeFeature("analytics")
                .build();

        assertTrue(license.hasFeature("export"));
        assertTrue(license.hasFeature("priority-support"));
        assertFalse(license.hasFeature("analytics"));

        license.clearFeatures();
        assertFalse(license.hasFeature("export"));
        assertEquals("", license.getFeaturesAsString().isEmpty() ? "" : license.getFeaturesAsString());
    }

    @Test
    void featuresRoundTripThroughStringRepresentation() {
        License license = new License();
        license.setFeaturesFromString("alpha,beta , gamma,,");

        assertTrue(license.hasFeature("alpha"));
        assertTrue(license.hasFeature("beta"));
        assertTrue(license.hasFeature("gamma"));

        String asString = license.getFeaturesAsString();
        License copy = new License();
        copy.setFeaturesFromString(asString);
        assertTrue(copy.hasFeature("gamma"));
    }

    @Test
    void licenseToStringUsesKeyAndLicensee() {
        License license = new License();
        license.setLicenseKey("LK-9");
        license.setLicenseeName("Acme");

        String text = license.toString();
        assertTrue(text.contains("LK-9"));
        assertTrue(text.contains("Acme"));
    }

    @Test
    void isExpiredReflectsExpirationDate() {
        License license = new License();
        license.setExpirationDate(java.time.LocalDateTime.now().minusDays(1));
        assertTrue(license.isExpired());

        license.setExpirationDate(java.time.LocalDateTime.now().plusDays(1));
        assertFalse(license.isExpired());
    }

    // ------------------------------------------------------------------
    // Default configuration defensive copies
    // ------------------------------------------------------------------

    @Test
    void defaultEncryptionConfigIsDefensivelyCopied() {
        EncryptionConfig original = new EncryptionConfig();
        original.setAesKeySize(128);
        Licify.setDefaultEncryptionConfig(original);

        // Mutating the caller's object must not change the shared default.
        original.setAesKeySize(192);
        assertEquals(128, Licify.getDefaultEncryptionConfig().getAesKeySize());

        // Returned copies are independent instances.
        EncryptionConfig view = Licify.getDefaultEncryptionConfig();
        view.setAesKeySize(256);
        assertEquals(128, Licify.getDefaultEncryptionConfig().getAesKeySize());

        // Null setter is a no-op.
        Licify.setDefaultEncryptionConfig(null);
        assertNotNull(Licify.getDefaultEncryptionConfig());

        // Restore factory default for other tests.
        Licify.setDefaultEncryptionConfig(new EncryptionConfig());
    }

    @Test
    void defaultSignatureConfigIsDefensivelyCopied() {
        SignatureConfig original = new SignatureConfig("SHA512withRSA", 4096, "SHA-512");
        Licify.setDefaultSignatureConfig(original);
        original.setKeyId("mutated-after-set");

        SignatureConfig current = Licify.getDefaultSignatureConfig();
        assertNull(current.getKeyId(), "external mutation must not leak into the default config");
        assertEquals("SHA512withRSA", current.getAlgorithm());

        Licify.setDefaultSignatureConfig(null); // no-op
        assertNotNull(Licify.getDefaultSignatureConfig());

        // Restore default for other tests.
        Licify.setDefaultSignatureConfig(new SignatureConfig());
    }

    // ------------------------------------------------------------------
    // Key pair wrapper
    // ------------------------------------------------------------------

    @Test
    void licenseKeyPairGenerateWrapsJavaKeyPair() throws Exception {
        LicenseKeyPair pair = LicenseKeyPair.generate();
        assertNotNull(pair.getPrivateKey());
        assertNotNull(pair.getPublicKey());
        assertSame(pair.getPrivateKey(), pair.getKeyPair().getPrivate());
        assertEquals("RSA", pair.getPublicKey().getAlgorithm());
    }

    @Test
    void licenseKeyPairStaticHelpersProduceUsableKeys() throws Exception {
        KeyPair rsa = LicenseKeyPair.generateRSAKeys(2048);
        assertNotNull(rsa.getPublic());

        SignatureConfig config = new SignatureConfig();
        KeyPair viaConfig = LicenseKeyPair.generateRSAKeys(config);
        assertNotNull(viaConfig.getPrivate());

        KeyPair viaProvider = LicenseKeyPair.generateKeyPair(config);
        assertNotNull(viaProvider.getPublic());

        javax.crypto.SecretKey aes = LicenseKeyPair.generateAESKey();
        assertEquals("AES", aes.getAlgorithm());
        assertEquals(32, aes.getEncoded().length, "AES-256 key material is 32 bytes");
    }

    @Test
    void unusableKeySizesAreRejected() {
        // JDK RSA accepts 512 bits (deprecated but supported); truly unusable
        // sizes such as 0 must raise.
        assertThrows(Exception.class, () -> LicenseKeyPair.generate(0));
    }
}
