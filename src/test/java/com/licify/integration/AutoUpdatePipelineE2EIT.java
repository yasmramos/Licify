package com.licify.integration;

import com.licify.Licify;
import com.licify.Licify.License;
import com.licify.core.AutoUpdateService;
import com.licify.encryption.EncryptionConfig;
import com.licify.signing.SignatureConfig;
// jdk.httpserver is made readable to the com.licify module during test
// compilation via --add-modules in the maven-compiler-plugin configuration.
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end test of the auto-update pipeline against a real HTTP server
 * (JDK's built-in {@code com.sun.net.httpserver.HttpServer}), so no network mocking library is
 * involved: check -> download -> checksum verification -> install callback,
 * exactly as a shipped application would run it.
 */
@DisplayName("E2E: auto-update pipeline over real HTTP")
class AutoUpdatePipelineE2EIT {

    private static HttpServer server;
    private static String baseUrl;

    /** Update payload served by the fake update endpoint. */
    private static final byte[] UPDATE_PAYLOAD =
            "LICIFY-DEMO-UPDATE-BINARY-CONTENT".getBytes(StandardCharsets.UTF_8);

    private static String payloadChecksum;

    @TempDir
    Path tempDir;

    @BeforeAll
    static void startServer() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        StringBuilder hex = new StringBuilder();
        for (byte b : digest.digest(UPDATE_PAYLOAD)) {
            hex.append(String.format("%02x", b));
        }
        payloadChecksum = hex.toString();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);

        server.createContext("/stable/version.json", exchange -> {
            String json = "{\"version\":\"9.9.0\",\"downloadUrl\":\"" + baseUrl
                    + "/stable/update.bin\",\"checksum\":\"" + payloadChecksum
                    + "\",\"fileSize\":" + UPDATE_PAYLOAD.length
                    + ",\"releaseNotes\":\"Integration test release\",\"critical\":false}";
            byte[] body = json.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });

        server.createContext("/same/version.json", exchange -> {
            // Advertises the very version the client already runs.
            String json = "{\"version\":\"1.0.0\",\"downloadUrl\":\"" + baseUrl
                    + "/stable/update.bin\",\"checksum\":\"" + payloadChecksum
                    + "\",\"fileSize\":" + UPDATE_PAYLOAD.length
                    + ",\"releaseNotes\":\"Same version\",\"critical\":false}";
            byte[] body = json.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });

        server.createContext("/broken/version.json", exchange -> {
            byte[] body = "not-json-at-all".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });

        server.createContext("/unavailable/version.json", exchange -> {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });

        server.createContext("/stable/update.bin", exchange -> {
            exchange.sendResponseHeaders(200, UPDATE_PAYLOAD.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(UPDATE_PAYLOAD);
            }
        });

        server.createContext("/corrupt/update.bin", exchange -> {
            // Serves different bytes than advertised -> checksum mismatch.
            byte[] wrong = "CORRUPTED-PAYLOAD".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, wrong.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(wrong);
            }
        });

        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        server.start();
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @BeforeEach
    void resetLicifyDefaults() {
        Licify.setDefaultSignatureConfig(new SignatureConfig());
        Licify.setDefaultEncryptionConfig(new EncryptionConfig());
    }

    private AutoUpdateService serviceFor(String path) {
        return new AutoUpdateService("1.0.0", baseUrl + path,
                tempDir.resolve("updates"));
    }

    @Test
    @DisplayName("detects an available update from the live metadata endpoint")
    void detectsNewerVersion() {
        AutoUpdateService service = serviceFor("/stable");
        AutoUpdateService.UpdateInfo info = service.checkForUpdates();

        assertNotNull(info, "a newer remote version must be reported");
        assertEquals("9.9.0", info.getVersion());
        assertFalse(info.isCritical());
        assertEquals(UPDATE_PAYLOAD.length, info.getFileSize());
    }

    @Test
    @DisplayName("reports no update when the remote version equals the current one")
    void noUpdateWhenAlreadyCurrent() {
        assertNull(serviceFor("/same").checkForUpdates(),
                "the same version must not trigger an update flow");
    }

    @Test
    @DisplayName("tolerates malformed and unavailable metadata endpoints without throwing")
    void handlesBadMetadataGracefully() {
        assertNull(serviceFor("/broken").checkForUpdates(),
                "malformed JSON must degrade to 'no update', never crash");
        assertNull(serviceFor("/unavailable").checkForUpdates(),
                "HTTP errors must degrade to 'no update'");
    }

    @Test
    @DisplayName("downloads, verifies checksum and installs the update end to end")
    void downloadVerifyAndInstall() {
        AutoUpdateService service = serviceFor("/stable");
        AutoUpdateService.UpdateInfo info = service.checkForUpdates();
        assertNotNull(info);

        AtomicInteger progressCalls = new AtomicInteger();
        boolean[] completed = new boolean[1];

        Path downloaded = service.downloadUpdate(info, new AutoUpdateService.ProgressListener() {
            @Override
            public void onDownloadStarted() { /* no-op */ }

            @Override
            public void onProgress(long bytesReceived, long totalBytes, int percentage) {
                progressCalls.incrementAndGet();
            }

            @Override
            public void onComplete(Path file) {
                completed[0] = true;
            }

            @Override
            public void onError(String message) {
                throw new AssertionError("unexpected download error: " + message);
            }
        });

        assertTrue(completed[0], "completion callback must fire on success");
        assertTrue(progressCalls.get() > 0, "progress callback must report at least one chunk");
        assertTrue(Files.exists(downloaded));

        // Checksum verification is part of downloadUpdate; re-check explicitly.
        assertTrue(service.verifyChecksum(downloaded, payloadChecksum));

        boolean installed = service.installUpdate(downloaded, () -> true);
        assertTrue(installed, "install callback result must be propagated");

        assertFalse(service.installUpdate(downloaded.resolveSibling("missing.jar"), () -> true),
                "installing a non-existent file must fail cleanly");
    }

    @Test
    @DisplayName("rejects downloads whose checksum does not match the metadata")
    void rejectsCorruptedDownload() {
        AutoUpdateService service = serviceFor("/stable");
        AutoUpdateService.UpdateInfo info = service.checkForUpdates();
        assertNotNull(info);

        // Point the download URL at the corrupt endpoint while keeping the
        // original (matching-the-good-payload) checksum in the metadata.
        AutoUpdateService.UpdateInfo tampered = new AutoUpdateService.UpdateInfo(
                info.getVersion(), baseUrl + "/corrupt/update.bin", info.getChecksum(),
                info.getFileSize(), info.getReleaseNotes(), info.isCritical());

        assertThrowsRuntimeException(() -> service.downloadUpdate(tampered, null));

        // The failed artifact must have been removed from disk.
        Path target = tempDir.resolve("updates").resolve("update_" + info.getVersion() + ".jar");
        assertFalse(Files.exists(target),
                "a corrupted download must never leave an installable file behind");
    }

    @Test
    @DisplayName("license verification still works after the update flow ran")
    void licenseFlowUnaffectedByUpdatePipeline() throws Exception {
        // Guards against accidental global state corruption between subsystems.
        License license = Licify.commercialLicense()
                .licenseeName("Post-Update Customer")
                .expirationDate(LocalDateTime.now().plusDays(30))
                .hardwareId(Licify.getHardwareId())
                .build();
        var keyPair = Licify.generateKeyPair();
        Licify.sign(license, keyPair);

        assertTrue(Licify.verify(license, keyPair.getPublic()));
    }

    private static void assertThrowsRuntimeException(Runnable action) {
        try {
            action.run();
        } catch (RuntimeException expected) {
            return;
        }
        throw new AssertionError("expected a RuntimeException but none was thrown");
    }
}
