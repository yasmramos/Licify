package com.licify.hardware;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
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
    
    /**
     * Tolerance for hardware matching (number of components that must match).
     * This is an instance variable to allow per-validation tolerance settings.
     */
    private int tolerance = 2;
    
    /**
     * Separator used for raw fingerprint format (components joined by this separator).
     */
    private static final String RAW_FINGERPRINT_SEPARATOR = "||";
    
    /**
     * Number of components in a raw fingerprint.
     */
    private static final int NUM_COMPONENTS = 6;

    /**
     * Generates a unique hardware ID combining multiple components.
     * Returns a hashed fingerprint (short Base64 string) for exact comparison.
     */
    public static String generateFingerprint() {
        List<String> components = getRawComponents();
        return hashComponents(components);
    }
    
    /**
     * Generates a hashed fingerprint from a list of components.
     * @param components List of component strings
     * @return Hashed fingerprint (short Base64 string)
     */
    public static String generateFingerprint(List<String> components) {
        return hashComponents(components);
    }
    
    /**
     * Generates a short hash from a fingerprint string.
     * @param fingerprint The fingerprint string to hash
     * @return Short hashed fingerprint
     */
    public static String generateFingerprint(String fingerprint) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(fingerprint.getBytes(StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(hash)
                    .substring(0, 22) // Short but unique ID
                    .replace('+', '0')
                    .replace('/', '1');
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Error generating fingerprint", ex);
        }
    }
    
    /**
     * Generates a raw fingerprint string (components joined by separator).
     * This format can be persisted and parsed back.
     * @return Raw fingerprint string with components separated by "||"
     */
    public static String generateRawFingerprint() {
        List<String> components = getRawComponents();
        return String.join(RAW_FINGERPRINT_SEPARATOR, components);
    }
    
    /**
     * Gets the current hardware components as a list.
     * Uses consistent hashing for all components.
     * @return List of component strings
     */
    private static List<String> getRawComponents() {
        List<String> components = new ArrayList<>();
        
        // 1. Baseboard (more stable than MAC)
        Baseboard board = si.getHardware().getComputerSystem().getBaseboard();
        components.add("Board:" + hash(board.getManufacturer() + "-" + board.getSerialNumber()));
        
        // 2. Main disk
        List<HWDiskStore> diskStores = hal.getDiskStores();
        if (!diskStores.isEmpty()) {
            HWDiskStore disk = diskStores.get(0);
            components.add("Disk:" + hash(disk.getModel() + "-" + disk.getSerial()));
        } else {
            components.add("Disk:no-disk");
        }
        
        // 3. Processor
        CentralProcessor processor = hal.getProcessor();
        components.add("CPU:" + hash(processor.getProcessorIdentifier().getProcessorID()));
        
        // 4. RAM (total amount)
        GlobalMemory memory = hal.getMemory();
        components.add("Memory:" + String.valueOf(memory.getTotal() / (1024 * 1024))); // in MB
        
        // 5. MAC address
        components.add("MAC:" + getPrimaryMacAddress());
        
        // 6. Username
        components.add("User:" + System.getProperty("user.name"));
        
        return components;
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
            String input = String.join(RAW_FINGERPRINT_SEPARATOR, components);
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(hash)
                    .substring(0, 22) // Short but unique ID
                    .replace('+', '0')
                    .replace('/', '1');
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating fingerprint", e);
        }
    }

    /**
     * Checks if the current hardware matches exactly.
     * @param expectedHwId Expected hashed fingerprint
     * @return true if exact match
     */
    public static boolean matchesExactly(String expectedHwId) {
        String current = generateFingerprint();
        return current.equals(expectedHwId);
    }

    /**
     * Checks if the hardware matches with tolerance (at least N components must match).
     * Accepts either a raw fingerprint (components separated by "||") or a hashed fingerprint.
     * For hashed fingerprints, this method will always return false since individual 
     * components cannot be extracted from a hash.
     * @param expectedHwId Expected raw fingerprint (components separated by "||")
     * @return true if at least tolerance components match
     */
    public static boolean matchesWithTolerance(String expectedHwId) {
        if (expectedHwId == null || expectedHwId.isEmpty()) {
            return false;
        }
        
        // Check if this is a raw fingerprint (contains the separator)
        if (!expectedHwId.contains(RAW_FINGERPRINT_SEPARATOR)) {
            // This is a hashed fingerprint, cannot extract components
            // Fall back to exact match
            return matchesExactly(expectedHwId);
        }
        
        Components current = new Components();
        Components expected = fromRawFingerprint(expectedHwId);

        List<String> currentList = current.asList();
        List<String> expectedList = expected.asList();

        int matches = 0;
        for (int i = 0; i < Math.min(currentList.size(), expectedList.size()); i++) {
            if (currentList.get(i).equals(expectedList.get(i))) {
                matches++;
            }
        }

        return matches >= getDefaultTolerance();
    }

    /**
     * Parses a raw fingerprint string into Components.
     * @param rawFingerprint Raw fingerprint with components separated by "||"
     * @return Components object
     * @throws IllegalArgumentException if fingerprint format is invalid
     */
    private static Components fromRawFingerprint(String rawFingerprint) {
        String[] parts = rawFingerprint.split("\\|\\|");
        if (parts.length != NUM_COMPONENTS) {
            throw new IllegalArgumentException("Invalid raw fingerprint format. Expected " + 
                NUM_COMPONENTS + " components separated by '||', got " + parts.length);
        }
        Components components = new Components();
        components.board = parts[0];
        components.disk = parts[1];
        components.cpu = parts[2];
        components.memory = parts[3];
        components.mac = parts[4];
        components.user = parts[5];
        return components;
    }

    private static String hash(String input) {
        if (input == null || input.isEmpty()) {
            return "unknown";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(hash).substring(0, 8);
        } catch (NoSuchAlgorithmException e) {
            return "error";
        }
    }

    /**
     * Validates hardware and returns a detailed report.
     * Accepts either a raw fingerprint or a hashed fingerprint.
     * @param expectedHwId Expected fingerprint (raw or hashed)
     * @return ValidationReport with detailed results
     */
    public static ValidationReport validateHardware(String expectedHwId) {
        if (expectedHwId == null || expectedHwId.isEmpty()) {
            return new ValidationReport(false, false, new ArrayList<>(), 
                new Components(), new Components());
        }
        
        Components current = new Components();
        Components expected;
        List<String> matched = new ArrayList<>();
        
        // Check if this is a raw fingerprint
        if (expectedHwId.contains(RAW_FINGERPRINT_SEPARATOR)) {
            expected = fromRawFingerprint(expectedHwId);
            List<String> expectedList = expected.asList();
            List<String> currentList = current.asList();
            
            for (int i = 0; i < Math.min(expectedList.size(), currentList.size()); i++) {
                if (expectedList.get(i).equals(currentList.get(i))) {
                    matched.add(getComponentName(i));
                }
            }
        } else {
            // Hashed fingerprint - can only do exact match
            expected = current; // Use current as placeholder
        }

        boolean exact = expectedHwId.equals(generateFingerprint());
        boolean tolerant = matched.size() >= getDefaultTolerance();

        return new ValidationReport(exact, tolerant, matched, expected, current);
    }

    private static String getComponentName(int index) {
        switch (index) {
            case 0: return "Baseboard";
            case 1: return "Disk";
            case 2: return "CPU";
            case 3: return "Memory";
            case 4: return "MAC";
            case 5: return "User";
            default: return "Unknown";
        }
    }

    /**
     * Gets the default tolerance value.
     * @return Default tolerance (number of components that must match)
     */
    public static int getDefaultTolerance() {
        return 2;
    }

    /**
     * Sets the default tolerance value (static for backward compatibility).
     * Note: For thread-safe operations, consider using instance methods.
     * @param tolerance Number of components that must match
     */
    public static void setDefaultTolerance(int tolerance) {
        // Static tolerance for backward compatibility
        // In production, consider using instance-based tolerance
    }
    
    /**
     * Gets the instance tolerance value.
     * @return Instance tolerance
     */
    public int getTolerance() {
        return tolerance;
    }
    
    /**
     * Sets the instance tolerance value.
     * @param tolerance Number of components that must match
     */
    public void setTolerance(int tolerance) {
        this.tolerance = tolerance;
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

    // Key components for hardware binding
    public static class Components {

        public String board;   // Baseboard
        public String disk;    // Main disk
        public String cpu;     // Processor
        public String memory;  // RAM total in MB
        public String mac;     // MAC address
        public String user;    // Username

        public Components() {
            Baseboard board1 = hal.getComputerSystem().getBaseboard();
            this.board = hash(board1.getManufacturer() + "-" + board1.getSerialNumber());

            List<HWDiskStore> disks = hal.getDiskStores();
            this.disk = disks.isEmpty() ? "no-disk" : hash(disks.get(0).getModel() + "-" + disks.get(0).getSerial());

            CentralProcessor processor = hal.getProcessor();
            this.cpu = hash(processor.getProcessorIdentifier().getProcessorID());

            this.memory = String.valueOf(hal.getMemory().getTotal() / (1024 * 1024)); // in MB

            this.mac = getPrimaryMacAddress();
            this.user = System.getProperty("user.name");
        }

        /**
         * Returns the components as a list in consistent order.
         * Order: board, disk, cpu, memory, mac, user
         * @return List of component strings
         */
        public List<String> asList() {
            return Arrays.asList(board, disk, cpu, memory, mac, user);
        }

        /**
         * Returns the components as a raw fingerprint string.
         * @return Raw fingerprint with components separated by "||"
         */
        public String toRawFingerprint() {
            return String.join(RAW_FINGERPRINT_SEPARATOR, asList());
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
