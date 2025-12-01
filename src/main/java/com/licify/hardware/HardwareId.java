package com.licify.hardware;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import oshi.SystemInfo;
import oshi.hardware.Baseboard;
import oshi.hardware.CentralProcessor;
import oshi.hardware.GlobalMemory;
import oshi.hardware.HWDiskStore;
import oshi.hardware.HardwareAbstractionLayer;
import oshi.software.os.OperatingSystem;

public class HardwareId {

    private static final SystemInfo si = new SystemInfo();
    private static final HardwareAbstractionLayer hal = si.getHardware();
    private static final OperatingSystem os = si.getOperatingSystem();
    private static int TOLERANCE = 2;

    /**
     * Genera un ID único de hardware combinando múltiples componentes
     */
    public static String generateFingerprint() {
        List<String> components = new ArrayList<>();

        // 1. Placa base (más estable que MAC)
        Baseboard board = si.getHardware().getComputerSystem().getBaseboard();
        components.add("Board:" + board.getManufacturer() + "-" + board.getSerialNumber());

        // 2. Disco principal
        List<HWDiskStore> diskStores = hal.getDiskStores();
        if (!diskStores.isEmpty()) {
            HWDiskStore disk = diskStores.get(0);
            components.add("Disk:" + disk.getModel() + "-" + disk.getSerial());
        }

        // 3. Procesador
        CentralProcessor processor = hal.getProcessor();
        components.add("CPU:" + processor.getProcessorIdentifier().getProcessorID());

        // 4. Memoria RAM (cantidad total)
        GlobalMemory memory = hal.getMemory();
        components.add("Memory:" + memory.getTotal());

        // 5. Sistema operativo
        components.add("OS:" + os.getFamily() + "-" + os.getVersionInfo().getVersion());

        // 6. Nombre de usuario (opcional)
        components.add("User:" + System.getProperty("user.name"));

        // 7. MAC address del primer adaptador activo
        components.add("MAC:" + getPrimaryMacAddress());

        // 8. Hash de todos los componentes
        return hashComponents(components);
    }

    public static String generateFingerprint(List<String> components) {
        return hashComponents(components);
    }

    public static String generateFingerprint(String fingerprint) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(fingerprint.getBytes());
            return java.util.Base64.getEncoder().encodeToString(hash)
                    .substring(0, 22) // ID corto pero único
                    .replace('+', '0')
                    .replace('/', '1');
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Error generando fingerprint", ex);
        }
    }

    private static String getPrimaryMacAddress() {
        return hal.getNetworkIFs(true).stream()
                .filter(nif -> nif.getMacaddr() != null && !nif.getMacaddr().isEmpty())
                .map(nif -> nif.getMacaddr())
                .findFirst()
                .orElse("no-mac");
    }

    private static String hashComponents(List<String> components) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String input = String.join("||", components);
            byte[] hash = md.digest(input.getBytes());
            return java.util.Base64.getEncoder().encodeToString(hash)
                    .substring(0, 22) // ID corto pero único
                    .replace('+', '0')
                    .replace('/', '1');
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generando fingerprint", e);
        }
    }

    /**
     * Verifica si el hardware actual coincide exactamente
     */
    public static boolean matchesExactly(String expectedHwId) {
        String current = generateFingerprint();
        return current.equals(expectedHwId);
    }

    /**
     * Verifica si el hardware coincide con tolerancia (al menos 2 componentes)
     */
    public static boolean matchesWithTolerance(String expectedHwId) {
        Components current = new Components();
        Components expected = fromFingerprint(expectedHwId);

        List<String> currentList = current.asList();
        List<String> expectedList = expected.asList();

        int matches = 0;
        for (int i = 0; i < currentList.size(); i++) {
            if (currentList.get(i).equals(expectedList.get(i))) {
                matches++;
            }
        }

        return matches >= TOLERANCE; // Puedes ajustar este umbral
    }

    /**
     * Recupera los componentes desde un fingerprint
     */
    private static Components fromFingerprint(String fingerprint) {
        String[] parts = fingerprint.split("\\|\\|");
        if (parts.length != 6) {
            throw new IllegalArgumentException("Fingerprint inválido");
        }
        return new Components() {
            {
                this.board = parts[0];
                this.disk = parts[1];
                this.cpu = parts[2];
                this.memory = parts[3];
                this.mac = parts[4];
                this.user = parts[5];
            }
        };
    }

    private static String hash(String input) {
        if (input == null || input.isEmpty()) {
            return "unknown";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes());
            return java.util.Base64.getEncoder().encodeToString(hash).substring(0, 8);
        } catch (NoSuchAlgorithmException e) {
            return "error";
        }
    }

    /**
     * Resultado detallado de la validación
     */
    public static ValidationReport validateHardware(String expectedHwId) {
        Components expected = fromFingerprint(expectedHwId);
        Components current = new Components();

        List<String> expectedList = expected.asList();
        List<String> currentList = current.asList();
        List<String> matched = new ArrayList<>();

        for (int i = 0; i < expectedList.size(); i++) {
            if (expectedList.get(i).equals(currentList.get(i))) {
                matched.add(getComponentName(i));
            }
        }

        boolean exact = expectedHwId.equals(generateFingerprint());
        boolean tolerant = matched.size() >= 2;

        return new ValidationReport(exact, tolerant, matched, expected, current);
    }

    private static String getComponentName(int index) {
        if (index == 0) {
            return "Placa base";
        }
        if (index == 1) {
            return "Disco";
        }
        if (index == 2) {
            return "CPU";
        }
        if (index == 3) {
            return "RAM";
        }
        if (index == 4) {
            return "MAC";
        }
        if (index == 5) {
            return "Usuario";
        }
        return "Desconocido";
    }

    public static int getTolerance() {
        return TOLERANCE;
    }

    public static void setTolerance(int tolerance) {
        HardwareId.TOLERANCE = tolerance;
    }

    public static class ValidationReport {

        public final boolean exactMatch;
        public final boolean tolerantMatch;
        public final List<String> matchedComponents;
        public final Components expected;
        public final Components actual;

        public ValidationReport(boolean exact, boolean tolerant, List<String> matched,
                Components expected, Components actual) {
            this.exactMatch = exact;
            this.tolerantMatch = tolerant;
            this.matchedComponents = matched;
            this.expected = expected;
            this.actual = actual;
        }

        public boolean isValid() {
            return exactMatch || tolerantMatch;
        }

        @Override
        public String toString() {
            return "ValidationReport{"
                    + "exactMatch=" + exactMatch
                    + ", tolerantMatch=" + tolerantMatch
                    + ", matchedComponents=" + matchedComponents
                    + '}';
        }
    }

    // Componentes clave para el ligado
    public static class Components {

        public String board;   // Placa base
        public String disk;    // Disco principal
        public String cpu;     // Procesador
        public String memory;  // RAM total
        public String mac;     // MAC address
        public String user;    // Usuario

        public Components() {
            Baseboard board1 = hal.getComputerSystem().getBaseboard();
            this.board = hash(board1.getSerialNumber());

            List<HWDiskStore> disks = hal.getDiskStores();
            this.disk = disks.isEmpty() ? "no-disk" : hash(disks.get(0).getSerial());

            CentralProcessor processor = hal.getProcessor();
            this.cpu = hash(processor.getProcessorIdentifier().getProcessorID());

            this.memory = String.valueOf(hal.getMemory().getTotal() / (1024 * 1024)); // en MB

            this.mac = getPrimaryMacAddress();
            this.user = System.getProperty("user.name");
        }

        public List<String> asList() {
            return Arrays.asList(board, disk, cpu, memory, mac, user);
        }

        @Override
        public String toString() {
            return "Components{"
                    + "board='" + board + '\''
                    + ", disk='" + disk + '\''
                    + ", cpu='" + cpu + '\''
                    + ", memory='" + memory + '\''
                    + ", mac='" + mac + '\''
                    + ", user='" + user + '\''
                    + '}';
        }
    }
}
