package com.licify.hardware;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link HardwareIdBackup} and remaining {@link HardwareId} helpers.
 */
class HardwareIdBackupTest {

    private static final String TEST_BACKUP_FILE = "target/test_hardware.id";

    @AfterEach
    void cleanUp() throws Exception {
        Files.deleteIfExists(Paths.get(TEST_BACKUP_FILE));
        // Restore the default backup location for other consumers.
        HardwareIdBackup.setBackupFile("hardware.id");
    }

    @Test
    void saveAndLoadRoundTrip() {
        HardwareIdBackup.setBackupFile(TEST_BACKUP_FILE);
        assertEquals(TEST_BACKUP_FILE, HardwareIdBackup.getBackupFile());

        HardwareIdBackup.save("hw-fingerprint-123");
        assertEquals("hw-fingerprint-123", HardwareIdBackup.load());
    }

    @Test
    void loadReturnsNullWhenFileIsAbsent() {
        HardwareIdBackup.setBackupFile("target/does-not-exist-" + System.nanoTime() + ".id");
        assertNull(HardwareIdBackup.load());
    }

    @Test
    void getOrGeneratePersistsFingerprintOnFirstCallAndReusesItAfterwards() {
        HardwareIdBackup.setBackupFile(TEST_BACKUP_FILE);
        Path path = Paths.get(TEST_BACKUP_FILE);

        String first = HardwareIdBackup.getOrGenerate();
        assertNotNull(first);
        assertFalse(first.isEmpty());
        assertTrue(Files.exists(path), "backup file must be created on first call");

        String second = HardwareIdBackup.getOrGenerate();
        assertEquals(first, second, "existing backup must be reused instead of regenerated");
    }

    @Test
    void saveToUnwritablePathDoesNotThrow() {
        // A directory that cannot exist forces an IOException in the catch branch.
        HardwareIdBackup.setBackupFile("/nonexistent-root-dir/hardware.id");
        assertDoesNotThrow(() -> HardwareIdBackup.save("value"));
        assertDoesNotThrow(HardwareIdBackup::load);
    }

    // ------------------------------------------------------------------
    // HardwareId helpers not covered elsewhere
    // ------------------------------------------------------------------

    @Test
    void instanceToleranceGetterAndSetter() {
        HardwareId hardwareId = new HardwareId();
        assertEquals(2, hardwareId.getTolerance(), "default instance tolerance is 2");
        hardwareId.setTolerance(4);
        assertEquals(4, hardwareId.getTolerance());
    }

    @Test
    void staticToleranceAccessorsAreBackwardCompatibleNoOps() {
        assertEquals(2, HardwareId.getDefaultTolerance());
        assertDoesNotThrow(() -> HardwareId.setDefaultTolerance(3));
        assertEquals(2, HardwareId.getDefaultTolerance());
    }

    @Test
    void validateHardwareWithNullReturnsEmptyInvalidReport() {
        HardwareId.ValidationReport report = HardwareId.validateHardware(null);
        assertFalse(report.exactMatch);
        assertFalse(report.isValid());
        assertTrue(report.matchedComponents.isEmpty());
        assertNotNull(report.toString());
    }

    @Test
    void componentsExposeOrderedListsAndRawFingerprints() {
        HardwareId.Components components = new HardwareId.Components();
        List<String> asList = components.asList();
        assertEquals(6, asList.size());
        assertEquals(components.board, asList.get(0));
        assertEquals(components.user, asList.get(5));

        String raw = components.toRawFingerprint();
        assertTrue(raw.contains("||"));
        assertEquals(String.join("||", asList), raw);
        assertNotNull(components.toString());
    }

    @Test
    void hashedFingerprintCannotUseToleranceButMatchesExactly() {
        String hashed = HardwareId.generateFingerprint();
        assertTrue(HardwareId.matchesExactly(hashed));
        // Hashed fingerprints have no extractable components: tolerance falls back to exact match.
        assertTrue(HardwareId.matchesWithTolerance(hashed));
        assertFalse(HardwareId.matchesWithTolerance(null));
        assertFalse(HardwareId.matchesWithTolerance(""));
    }

    @Test
    void rawFingerprintFromCurrentMachineMatchesWithFullTolerance() {
        // Build a raw fingerprint from a fresh Components snapshot: two OSHI
        // samplings can disagree on volatile fields (MAC list, disks), so use a
        // single consistent snapshot for the tolerance check instead.
        String raw = new HardwareId.Components().toRawFingerprint();
        assertTrue(HardwareId.matchesWithTolerance(raw));

        HardwareId.ValidationReport report = HardwareId.validateHardware(raw);
        assertTrue(report.tolerantMatch, "report: " + report);
        assertTrue(report.isValid());
        assertTrue(report.matchedComponents.size() >= HardwareId.getDefaultTolerance());
    }

    @Test
    void generateFingerprintFromComponentListIsDeterministic() {
        List<String> components = List.of("Board:x", "Disk:y", "CPU:z", "Memory:1024", "MAC:aa", "User:bb");
        String first = HardwareId.generateFingerprint(components);
        String second = HardwareId.generateFingerprint(components);
        assertEquals(first, second);
        assertEquals(22, first.length());
    }
}
