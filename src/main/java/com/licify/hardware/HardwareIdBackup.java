package com.licify.hardware;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class HardwareIdBackup {

    private static String BACKUP_FILE = "hardware.id";

    /**
     * Guarda el hardwareId en disco
     * @param hardwareId
     */
    public static void save(String hardwareId) {
        try {
            Files.write(
                Paths.get(BACKUP_FILE),
                hardwareId.getBytes(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
            );
        } catch (IOException e) {
            System.err.println("❌ No se pudo guardar hardware.id: " + e.getMessage());
        }
    }

    /**
     * Carga el hardwareId desde disco
     * @return 
     */
    public static String load() {
        try {
            if (Files.exists(Paths.get(BACKUP_FILE))) {
                return new String(Files.readAllBytes(Paths.get(BACKUP_FILE)));
            }
        } catch (IOException e) {
            System.err.println("❌ No se pudo cargar hardware.id: " + e.getMessage());
        }
        return null;
    }

    /**
     * Genera y guarda un nuevo ID si no existe
     * @return 
     */
    public static String getOrGenerate() {
        String saved = load();
        if (saved != null) {
            return saved;
        }
        String newId = HardwareId.generateFingerprint();
        save(newId);
        return newId;
    }

    public static String getBackupFile() {
        return BACKUP_FILE;
    }

    public static void setBackupFile(String backupFile) {
        HardwareIdBackup.BACKUP_FILE = backupFile;
    }
    
    
}