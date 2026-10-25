package com.licify.encryption;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link HybridEncryption} (RSA + AES-GCM hybrid scheme)
 * and {@link EncryptionConfig}.
 */
class HybridEncryptionTest {

    private static KeyPair rsaKeyPair;
    private static final byte[] PLAINTEXT =
            "license-payload-to-protect".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        rsaKeyPair = generator.generateKeyPair();
    }

    private static EncryptionConfig defaultConfig() {
        return new EncryptionConfig();
    }

    // ------------------------------------------------------------------
    // End-to-end hybrid encrypt / decrypt
    // ------------------------------------------------------------------

    @Test
    void hybridRoundTripWithDefaultConfigRecoversPlaintext() throws Exception {
        HybridEncryption engine = new HybridEncryption(defaultConfig());
        PublicKey publicKey = rsaKeyPair.getPublic();
        PrivateKey privateKey = rsaKeyPair.getPrivate();

        HybridEncryptionResult result = engine.hybridEncrypt(PLAINTEXT, publicKey);
        assertNotNull(result.getEncryptedAesKey());
        assertNotNull(result.getEncryptedData());
        assertNotSame(PLAINTEXT, result.getEncryptedData());

        byte[] decrypted = engine.hybridDecrypt(result, privateKey);
        assertArrayEquals(PLAINTEXT, decrypted);
    }

    @Test
    void hybridRoundTripWithExplicitConfigRecoversPlaintext() throws Exception {
        EncryptionConfig config = EncryptionConfig.builder().aesKeySize(128).build();
        HybridEncryption engine = new HybridEncryption(defaultConfig());

        HybridEncryptionResult result =
                engine.hybridEncrypt(PLAINTEXT, rsaKeyPair.getPublic(), config);
        byte[] decrypted = engine.hybridDecrypt(result, rsaKeyPair.getPrivate(), config);

        assertArrayEquals(PLAINTEXT, decrypted);
    }

    @Test
    void decryptionWithWrongPrivateKeyFails() throws Exception {
        HybridEncryption engine = new HybridEncryption(defaultConfig());
        HybridEncryptionResult result = engine.hybridEncrypt(PLAINTEXT, rsaKeyPair.getPublic());

        KeyPairGenerator other = KeyPairGenerator.getInstance("RSA");
        other.initialize(2048);
        PrivateKey wrongKey = other.generateKeyPair().getPrivate();

        assertThrows(Exception.class, () -> engine.hybridDecrypt(result, wrongKey));
    }

    // ------------------------------------------------------------------
    // AES primitives
    // ------------------------------------------------------------------

    @Test
    void aesRoundTripInstanceMethods() throws Exception {
        HybridEncryption engine = new HybridEncryption(defaultConfig());
        SecretKey key = engine.generateAesKey();
        assertEquals("AES", key.getAlgorithm());

        byte[] encrypted = engine.encryptWithAes(PLAINTEXT, key);
        byte[] decrypted = engine.decryptWithAes(encrypted, key);
        assertArrayEquals(PLAINTEXT, decrypted);
    }

    @Test
    void aesRoundTripStaticMethodsWithConfig() throws Exception {
        EncryptionConfig config = defaultConfig();
        HybridEncryption engine = new HybridEncryption(config);
        SecretKey key = engine.generateAesKey(192);

        byte[] encrypted = engine.encryptWithAes(PLAINTEXT, key, config);
        byte[] decrypted = HybridEncryption.decryptWithAes(encrypted, key, config);
        assertArrayEquals(PLAINTEXT, decrypted);
    }

    @Test
    void generatedAesKeysAreDistinctAndRandomIvProducesDifferentCiphertexts() throws Exception {
        HybridEncryption engine = new HybridEncryption(defaultConfig());
        SecretKey key = engine.generateAesKey(256);

        byte[] first = engine.encryptWithAes(PLAINTEXT, key);
        byte[] second = engine.encryptWithAes(PLAINTEXT, key);

        // Random IV per call must produce different ciphertexts for the same input.
        assertFalse(java.util.Arrays.equals(first, second));
        assertArrayEquals(PLAINTEXT, engine.decryptWithAes(first, key));
        assertArrayEquals(PLAINTEXT, engine.decryptWithAes(second, key));
    }

    @Test
    void decryptWithAesRejectsTruncatedPayload() {
        EncryptionConfig config = defaultConfig();
        SecretKey key = new SecretKeySpec(new byte[32], "AES");
        byte[] tooShort = new byte[config.getGcmIvLength() - 1];

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> HybridEncryption.decryptWithAes(tooShort, key, config));
        assertTrue(ex.getMessage().contains("too short"));
    }

    @Test
    void decryptWithAesRejectsNullPayload() {
        SecretKey key = new SecretKeySpec(new byte[32], "AES");
        assertThrows(IllegalArgumentException.class,
                () -> HybridEncryption.decryptWithAes(null, key, defaultConfig()));
    }

    @Test
    void tamperedCiphertextIsRejectedByGcmTag() throws Exception {
        HybridEncryption engine = new HybridEncryption(defaultConfig());
        SecretKey key = engine.generateAesKey();
        byte[] encrypted = engine.encryptWithAes(PLAINTEXT, key);
        // Flip a bit in the ciphertext body (after the IV).
        encrypted[encrypted.length - 1] ^= 0x01;

        assertThrows(Exception.class, () -> engine.decryptWithAes(encrypted, key));
    }

    // ------------------------------------------------------------------
    // RSA key-wrapping primitives
    // ------------------------------------------------------------------

    @Test
    void rsaWrapUnwrapOfAesKey() throws Exception {
        HybridEncryption engine = new HybridEncryption(defaultConfig());
        SecretKey aesKey = engine.generateAesKey();

        byte[] wrapped = engine.encryptAesKeyWithRsa(aesKey, rsaKeyPair.getPublic());
        SecretKey unwrapped = engine.decryptAesKeyWithRsa(wrapped, rsaKeyPair.getPrivate());

        assertArrayEquals(aesKey.getEncoded(), unwrapped.getEncoded());
        assertEquals("AES", unwrapped.getAlgorithm());
    }

    @Test
    void staticRsaHelpersMatchInstanceBehavior() throws Exception {
        EncryptionConfig config = defaultConfig();
        HybridEncryption engine = new HybridEncryption(config);
        SecretKey aesKey = engine.generateAesKey();

        byte[] wrapped = HybridEncryption.encryptAesKeyWithRsa(
                aesKey, rsaKeyPair.getPublic(), config);
        SecretKey unwrapped = HybridEncryption.decryptAesKeyWithRsa(
                wrapped, rsaKeyPair.getPrivate(), config);

        assertArrayEquals(aesKey.getEncoded(), unwrapped.getEncoded());
    }

    // ------------------------------------------------------------------
    // EncryptionConfig coverage (builder, setters, copy)
    // ------------------------------------------------------------------

    @Test
    void encryptionConfigDefaults() {
        EncryptionConfig config = new EncryptionConfig();
        assertEquals("RSA", config.getRsaAlgorithm());
        assertEquals("RSA/ECB/PKCS1Padding", config.getRsaTransformation());
        assertEquals("AES", config.getAesAlgorithm());
        assertEquals("AES/GCM/NoPadding", config.getAesTransformation());
        assertEquals(256, config.getAesKeySize());
        assertEquals(128, config.getGcmTagLength());
        assertEquals(12, config.getGcmIvLength());
    }

    @Test
    void encryptionConfigBuilderSetsEveryField() {
        EncryptionConfig config = EncryptionConfig.builder()
                .rsaAlgorithm("RSA")
                .rsaTransformation("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
                .aesAlgorithm("AES")
                .aesTransformation("AES/GCM/NoPadding")
                .aesKeySize(128)
                .gcmTagLength(120)
                .gcmIvLength(16)
                .build();

        assertEquals("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", config.getRsaTransformation());
        assertEquals(128, config.getAesKeySize());
        assertEquals(120, config.getGcmTagLength());
        assertEquals(16, config.getGcmIvLength());
    }

    @Test
    void encryptionConfigSettersMutateValues() {
        EncryptionConfig config = new EncryptionConfig();
        config.setRsaAlgorithm("RSA");
        config.setRsaTransformation("RSA/ECB/PKCS1Padding");
        config.setAesAlgorithm("AES");
        config.setAesTransformation("AES/GCM/NoPadding");
        config.setAesKeySize(192);
        config.setGcmTagLength(96);
        config.setGcmIvLength(12);

        assertEquals(192, config.getAesKeySize());
        assertEquals(96, config.getGcmTagLength());
    }

    @Test
    void encryptionConfigCopyIsDefensive() {
        EncryptionConfig original = new EncryptionConfig();
        EncryptionConfig copy = original.copy();

        assertNotSame(original, copy);
        assertEquals(original.getAesKeySize(), copy.getAesKeySize());
        assertEquals(original.getRsaTransformation(), copy.getRsaTransformation());

        copy.setAesKeySize(128);
        assertEquals(256, original.getAesKeySize(), "mutating the copy must not affect the original");
    }
}
