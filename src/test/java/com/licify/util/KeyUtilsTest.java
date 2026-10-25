package com.licify.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link KeyUtils} (PEM public-key loading helpers).
 */
class KeyUtilsTest {

    @TempDir
    Path tempDir;

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String toPem(PublicKey publicKey) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n";
    }

    @Test
    void loadPublicKeyFromFileParsesPemRoundTrip() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        Path pemFile = tempDir.resolve("public.pem");
        Files.writeString(pemFile, toPem(keyPair.getPublic()));

        PublicKey loaded = KeyUtils.loadPublicKeyFromFile(pemFile.toString());

        assertNotNull(loaded);
        assertArrayEquals(keyPair.getPublic().getEncoded(), loaded.getEncoded());
    }

    @Test
    void loadPublicKeyFromResourceFallsBackToFileSystem() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        // The name does not exist on the classpath, but exists relative to the
        // working directory -> the file-system fallback branch must kick in.
        Path fileName = tempDir.resolve("fallback.pem");
        Files.writeString(fileName, toPem(keyPair.getPublic()));
        Path linked = Paths.get("licify-test-fallback.pem").toAbsolutePath();
        Files.copy(fileName, linked, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        try {
            PublicKey loaded = KeyUtils.loadPublicKeyFromResource("/licify-test-fallback.pem");

            assertNotNull(loaded);
            assertArrayEquals(keyPair.getPublic().getEncoded(), loaded.getEncoded());
        } finally {
            Files.deleteIfExists(linked);
        }
    }

    @Test
    void loadPublicKeyFromResourceLoadsClasspathEntry() {
        // The test-classes directory is on the classpath and contains compiled
        // test resources; a missing path must return null instead of throwing.
        PublicKey missing = KeyUtils.loadPublicKeyFromResource("/definitely-not-present.pem");
        assertNull(missing);
    }

    @Test
    void loadPublicKeyFromFileRejectsMissingFile() {
        assertThrows(IOException.class,
                () -> KeyUtils.loadPublicKeyFromFile(tempDir.resolve("absent.pem").toString()));
    }

    @Test
    void loadPublicKeyFromFileRejectsGarbageContent() throws Exception {
        Path bad = tempDir.resolve("bad.pem");
        Files.writeString(bad, "not a pem at all");
        assertThrows(Exception.class, () -> KeyUtils.loadPublicKeyFromFile(bad.toString()));
    }
}
