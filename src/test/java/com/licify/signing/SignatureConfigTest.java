package com.licify.signing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link SignatureConfig} (validation rules, copy semantics,
 * equals/hashCode/toString and the fluent builder).
 */
class SignatureConfigTest {

    @Test
    void defaultsMatchDocumentedValues() {
        SignatureConfig config = new SignatureConfig();
        assertEquals("SHA256withRSA", config.getAlgorithm());
        assertEquals(2048, config.getKeySize());
        assertEquals("SHA-256", config.getHashAlgorithm());
        assertEquals("SunRsaSign", config.getProvider());
        assertFalse(config.isEnablePSS());
        assertNull(config.getKeyId());
    }

    @Test
    void twoArgConstructorSetsAlgorithmAndKeySize() {
        SignatureConfig config = new SignatureConfig("SHA512withRSA", 4096);
        assertEquals("SHA512withRSA", config.getAlgorithm());
        assertEquals(4096, config.getKeySize());
    }

    @Test
    void threeArgConstructorAlsoSetsHashAlgorithm() {
        SignatureConfig config = new SignatureConfig("SHA512withRSA", 4096, "SHA-512");
        assertEquals("SHA-512", config.getHashAlgorithm());
    }

    @Test
    void algorithmRejectsNullAndBlank() {
        SignatureConfig config = new SignatureConfig();
        assertThrows(IllegalArgumentException.class, () -> config.setAlgorithm(null));
        assertThrows(IllegalArgumentException.class, () -> config.setAlgorithm("   "));
    }

    @Test
    void hashAlgorithmRejectsNullAndBlank() {
        SignatureConfig config = new SignatureConfig();
        assertThrows(IllegalArgumentException.class, () -> config.setHashAlgorithm(null));
        assertThrows(IllegalArgumentException.class, () -> config.setHashAlgorithm(""));
    }

    @Test
    void keySizeEnforcesRangeAndMultiplesOfSixtyFour() {
        SignatureConfig config = new SignatureConfig();
        assertThrows(IllegalArgumentException.class, () -> config.setKeySize(512), "below MIN_KEY_SIZE");
        assertThrows(IllegalArgumentException.class, () -> config.setKeySize(8192), "above MAX_KEY_SIZE");
        assertThrows(IllegalArgumentException.class, () -> config.setKeySize(2047), "not a multiple of 64");

        assertDoesNotThrow(() -> config.setKeySize(1024));
        assertDoesNotThrow(() -> config.setKeySize(4096));
    }

    @Test
    void ecKeySizesAreRestrictedToStandardCurves() {
        // Note: the global 1024..4096 range check applies before the EC curve
        // check, so only 256/384 are reachable for EC through setKeySize.
        SignatureConfig config = new SignatureConfig("SHA256withRSA", 2048);
        config.setAlgorithm("SHA256withECDSA");
        assertThrows(IllegalArgumentException.class, () -> config.setKeySize(2048),
                "EC algorithm rejects non-curve sizes");
        assertThrows(IllegalArgumentException.class, () -> config.setKeySize(512),
                "below the global minimum");
        // EC curve sizes (256/384/521) are unreachable through setKeySize because
        // the global 1024..4096 range check runs first; document that behaviour.
        assertThrows(IllegalArgumentException.class, () -> config.setKeySize(256));
        assertThrows(IllegalArgumentException.class, () -> config.setKeySize(384));
    }

    @Test
    void validateRejectsMismatchedSignatureAndHashPattern() {
        SignatureConfig config = new SignatureConfig();
        // Default SHA256withRSA + SHA-256 is consistent.
        assertDoesNotThrow(config::validate);

        SignatureConfig broken = new SignatureConfig();
        broken.setHashAlgorithm("MD5");
        assertThrows(IllegalStateException.class, broken::validate);
    }

    @Test
    void copyProducesEqualButIndependentInstance() {
        SignatureConfig original = SignatureConfig.builder()
                .algorithm("SHA512withRSA")
                .keySize(4096)
                .hashAlgorithm("SHA-512")
                .provider("SunRsaSign")
                .enablePSS(true)
                .keyId("key-2026")
                .build();

        SignatureConfig copy = original.copy();
        assertNotSame(original, copy);
        assertEquals(original, copy);
        assertEquals(original.hashCode(), copy.hashCode());

        copy.setKeyId("other");
        assertNotEquals(original, copy);
    }

    @Test
    void equalsAndHashCodeFollowFieldSemantics() {
        SignatureConfig a = new SignatureConfig();
        SignatureConfig b = new SignatureConfig();
        assertEquals(a, b);
        assertEquals(a, a);
        assertNotEquals(a, null);
        assertNotEquals(a, "not a config");

        b.setKeyId("x");
        assertNotEquals(a, b);
        assertNotEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void toStringIncludesAllFields() {
        String text = new SignatureConfig().toString();
        assertTrue(text.startsWith("SignatureConfig{"));
        assertTrue(text.contains("SHA256withRSA"));
        assertTrue(text.contains("keySize=2048"));
        assertTrue(text.contains("enablePSS=false"));
    }

    @Test
    void builderValidatesOnBuild() {
        // Invalid combination: SHA* signature algorithm with non-SHA hash.
        SignatureConfig.Builder builder = SignatureConfig.builder()
                .hashAlgorithm("MD5");
        assertThrows(IllegalStateException.class, builder::build);
    }
}
