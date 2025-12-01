package com.licify;

import com.licify.core.LicenseRevocationManager;
import com.licify.core.LicenseSerializer;
import com.licify.core.ShortLicenseKey;
import com.licify.encryption.EncryptionConfig;
import com.licify.encryption.HybridEncryption;
import com.licify.encryption.HybridEncryptionResult;
import com.licify.hardware.HardwareId;
import com.licify.io.IOFormat;
import com.licify.signing.SignatureConfig;
import com.licify.util.DateTimeUtils;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.*;
import javax.crypto.Cipher;

/**
 * Biblioteca de gestión de licencias con soporte completo para firmas
 */
public class Licify {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final LicenseRevocationManager revocationManager = LicenseRevocationManager.getInstance();
    private static SignatureConfig defaultSignatureConfig = new SignatureConfig();
    private static EncryptionConfig defaultEncryptionConfig = new EncryptionConfig();
    private static String hardwareIdCache = null;

    public static License createFromSeed(String seed) {
        License license = new License();
        license.setCustomData(seed);
        return license;
    }

    public static License createLicenseFromText(String licenseText) {
        return null;
    }

    /**
     * Clase que representa una licencia
     */
    public static class License implements Serializable {

        private static final long serialVersionUID = 7735990574904268943L;
        private String licenseeName;
        private String licenseeEmail;
        private LocalDateTime issueDate;
        private LocalDateTime expirationDate;
        private String productId;
        private String productVersion;
        private String licenseKey;
        private String signature;
        private String signatureAlgorithm;
        private String publicKeyFingerprint;
        private boolean trial;
        private int maxUsers;
        private Set<String> features;
        private String customData;
        private String licenseType;
        private String version;
        private String hardwareId;
        private String licenseFile;

        public License() {
            this.issueDate = LocalDateTime.now();
            this.version = "1.0";
            this.features = new LinkedHashSet<>();
        }

        public String getLicenseFile() {
            return licenseFile;
        }

        public void setLicenseFile(String licenseFile) {
            this.licenseFile = licenseFile;
        }

        public String getLicenseeName() {
            return licenseeName;
        }

        public void setLicenseeName(String licenseeName) {
            this.licenseeName = licenseeName;
        }

        public String getLicenseeEmail() {
            return licenseeEmail;
        }

        public void setLicenseeEmail(String licenseeEmail) {
            this.licenseeEmail = licenseeEmail;
        }

        public LocalDateTime getIssueDate() {
            return issueDate;
        }

        public void setIssueDate(LocalDateTime issueDate) {
            this.issueDate = issueDate;
        }

        public LocalDateTime getExpirationDate() {
            return expirationDate;
        }

        public void setExpirationDate(LocalDateTime expirationDate) {
            this.expirationDate = expirationDate;
        }

        public String getProductId() {
            return productId;
        }

        public void setProductId(String productId) {
            this.productId = productId;
        }

        public String getProductVersion() {
            return productVersion;
        }

        public void setProductVersion(String productVersion) {
            this.productVersion = productVersion;
        }

        public String getLicenseKey() {
            return licenseKey;
        }

        public void setLicenseKey(String licenseKey) {
            this.licenseKey = licenseKey;
        }

        public String getSignature() {
            return signature;
        }

        public void setSignature(String signature) {
            this.signature = signature;
        }

        public String getSignatureAlgorithm() {
            return signatureAlgorithm;
        }

        public void setSignatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
        }

        public String getPublicKeyFingerprint() {
            return publicKeyFingerprint;
        }

        public void setPublicKeyFingerprint(String publicKeyFingerprint) {
            this.publicKeyFingerprint = publicKeyFingerprint;
        }

        public boolean isTrial() {
            return trial;
        }

        public void setTrial(boolean trial) {
            this.trial = trial;
        }

        public int getMaxUsers() {
            return maxUsers;
        }

        public void setMaxUsers(int maxUsers) {
            this.maxUsers = maxUsers;
        }

        public Set<String> getFeatures() {
            return features;
        }

        public void setFeatures(Set<String> features) {
            this.features = features;
        }

        public void addFeature(String feature) {
            this.features.add(feature);
        }

        public void removeFeature(String feature) {
            this.features.remove(feature);
        }

        public boolean hasFeature(String feature) {
            return this.features.contains(feature);
        }

        public void clearFeatures() {
            this.features.clear();
        }

        public String getFeaturesAsString() {
            return String.join(",", features);
        }

        public boolean isExpired() {
            if (expirationDate == null) {
                return true; // Considerar nulo como expirado
            }
            return LocalDateTime.now().isAfter(expirationDate);
        }

        public void setFeaturesFromString(String featuresString) {
            if (featuresString != null && !featuresString.isEmpty()) {
                String[] featureArray = featuresString.split(",");
                this.features.clear();
                for (String feature : featureArray) {
                    this.features.add(feature.trim());
                }
            } else {
                this.features.clear();
            }
        }

        public String getCustomData() {
            return customData;
        }

        public void setCustomData(String customData) {
            this.customData = customData;
        }

        public String getLicenseType() {
            return licenseType;
        }

        public void setLicenseType(String licenseType) {
            this.licenseType = licenseType;
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            this.version = version;
        }

        public String getHardwareId() {
            return hardwareId;
        }

        public void setHardwareId(String hardwareId) {
            this.hardwareId = hardwareId;
        }

        public void setIsTrial(boolean isTrial) {
            this.trial = isTrial;
        }

    }

    /**
     * Builder para crear licencias de forma fluida
     */
    public static class LicenseBuilder {

        private final License license;

        public LicenseBuilder() {
            this.license = new License();
        }

        public LicenseBuilder licenseeName(String licenseeName) {
            license.setLicenseeName(licenseeName);
            return this;
        }

        public LicenseBuilder licenseeEmail(String licenseeEmail) {
            license.setLicenseeEmail(licenseeEmail);
            return this;
        }

        public LicenseBuilder productId(String productId) {
            license.setProductId(productId);
            return this;
        }

        public LicenseBuilder productVersion(String productVersion) {
            license.setProductVersion(productVersion);
            return this;
        }

        public LicenseBuilder expirationDate(LocalDateTime expirationDate) {
            license.setExpirationDate(expirationDate);
            return this;
        }

        public LicenseBuilder maxUsers(int maxUsers) {
            license.setMaxUsers(maxUsers);
            return this;
        }

        public LicenseBuilder features(Set<String> features) {
            license.setFeatures(features);
            return this;
        }

        public LicenseBuilder feature(String feature) {
            license.addFeature(feature);
            return this;
        }

        public LicenseBuilder removeFeature(String feature) {
            license.removeFeature(feature);
            return this;
        }

        public LicenseBuilder customData(String customData) {
            license.setCustomData(customData);
            return this;
        }

        public LicenseBuilder licenseType(String licenseType) {
            license.setLicenseType(licenseType);
            return this;
        }

        public LicenseBuilder hardwareId(String hardwareId) {
            license.setHardwareId(HardwareId.generateFingerprint(hardwareId));
            return this;
        }

        public LicenseBuilder hardwareId() {
            license.setHardwareId(HardwareId.generateFingerprint());
            return this;
        }

        public LicenseBuilder trial(boolean isTrial) {
            license.setTrial(isTrial);
            return this;
        }

        public License build() {
            if (license.getLicenseKey() == null) {
                license.setLicenseKey(generateLicenseId());
            }
            if (license.getIssueDate() == null) {
                license.setIssueDate(LocalDateTime.now());
            }
            // Establecer valores por defecto si no se han configurado
            if (license.getLicenseType() == null) {
                license.setLicenseType("COMMERCIAL");
            }
            if (license.getHardwareId() == null) {
                license.setHardwareId(getHardwareId());
            }

            if (license.getLicenseFile() != null && !license.getLicenseFile().isEmpty()) {
                try {
                    save(license, license.getLicenseFile());
                } catch (Exception ex) {
                    System.getLogger(Licify.class.getName()).log(System.Logger.Level.ERROR, "Error al guardar la licencia", ex);
                }
            }
            return license;
        }

        public LicenseBuilder file(String licenseFile) {
            Objects.requireNonNull(licenseFile, "El archivo de licencia no puede ser nulo");
            this.license.setLicenseFile(licenseFile);
            return this;
        }
    }

    /**
     * Establece la configuración por defecto de cifrado
     */
    public static void setDefaultEncryptionConfig(EncryptionConfig config) {
        if (config != null) {
            defaultEncryptionConfig = config;
        }
    }

    /**
     * Obtiene la configuración por defecto de cifrado
     */
    public static EncryptionConfig getDefaultEncryptionConfig() {
        return defaultEncryptionConfig;
    }

    /**
     * Cifra y guarda una licencia de forma segura
     */
    public static void saveEncryptedLicense(License license, String filePath, PublicKey publicKey) throws Exception {
        saveEncryptedLicense(license, filePath, publicKey, defaultEncryptionConfig);
    }

    public static void saveEncryptedLicense(License license, String filePath, PublicKey publicKey, EncryptionConfig config) throws Exception {
        // Serializar licencia
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(license);
        }
        byte[] licenseData = baos.toByteArray();

        // Cifrar híbridamente
        HybridEncryptionResult encrypted = new HybridEncryption(defaultEncryptionConfig).hybridEncrypt(licenseData, publicKey, config);

        // Guardar resultado cifrado
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath))) {
            oos.writeObject(encrypted);
        }
    }

    /**
     * Carga y descifra una licencia
     */
    public static License loadEncryptedLicense(String filePath, PrivateKey privateKey) throws Exception {
        return loadEncryptedLicense(filePath, privateKey, defaultEncryptionConfig);
    }

    public static License loadEncryptedLicense(String filePath, PrivateKey privateKey, EncryptionConfig config) throws Exception {
        // Cargar datos cifrados
        HybridEncryptionResult encrypted;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            encrypted = (HybridEncryptionResult) ois.readObject();
        }

        // Descifrar
        byte[] decryptedData = new HybridEncryption(defaultEncryptionConfig).hybridDecrypt(encrypted, privateKey, config);

        // Deserializar licencia
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decryptedData))) {
            return (License) ois.readObject();
        }
    }

    /**
     * Establece la configuración por defecto de firma
     */
    public static void setDefaultSignatureConfig(SignatureConfig config) {
        if (config != null) {
            defaultSignatureConfig = config.copy();
        }
    }

    /**
     * Obtiene la configuración por defecto de firma
     */
    public static SignatureConfig getDefaultSignatureConfig() {
        return defaultSignatureConfig.copy();
    }

    /**
     * Crea una licencia firmada digitalmente usando configuración por defecto
     */
    public static License sign(License license, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        return sign(license, privateKey, publicKey, defaultSignatureConfig);
    }

    public static License sign(License license, KeyPair keyPair) throws Exception {
        return sign(license, keyPair.getPrivate(), keyPair.getPublic(), defaultSignatureConfig);
    }

    /**
     * Crea una licencia firmada digitalmente con configuración específica
     */
    public static License sign(License license, PrivateKey privateKey, PublicKey publicKey, SignatureConfig config) throws Exception {
        if (config == null) {
            config = defaultSignatureConfig;
        }

        String licenseData = serializeLicense(license);
        Signature signature = Signature.getInstance(config.getAlgorithm(), config.getProvider());
        signature.initSign(privateKey);
        signature.update(licenseData.getBytes(StandardCharsets.UTF_8));
        byte[] sig = signature.sign();

        license.setSignature(Base64.getEncoder().encodeToString(sig));
        license.setSignatureAlgorithm(config.getAlgorithm());

        if (publicKey != null) {
            license.setPublicKeyFingerprint(calculatePublicKeyFingerprint(publicKey, config.getHashAlgorithm()));
        }

        return license;
    }

    /**
     * Crea una licencia firmada digitalmente (para backward compatibility) Sin
     * fingerprint de clave pública
     */
    public static License sign(License license, PrivateKey privateKey) throws Exception {
        if (defaultSignatureConfig == null) {
            throw new IllegalStateException("Default signature configuration not set");
        }

        String licenseData = serializeLicense(license);
        Signature signature = Signature.getInstance(defaultSignatureConfig.getAlgorithm(),
                defaultSignatureConfig.getProvider());
        signature.initSign(privateKey);
        signature.update(licenseData.getBytes(StandardCharsets.UTF_8));
        byte[] sig = signature.sign();

        license.setSignature(Base64.getEncoder().encodeToString(sig));
        license.setSignatureAlgorithm(defaultSignatureConfig.getAlgorithm());

        // No se puede generar fingerprint sin la clave pública
        System.out.println("Warning: License created without public key fingerprint. "
                + "Use sign(license, privateKey, publicKey) for full functionality.");

        return license;
    }

    /**
     * Verifica la firma de una licencia usando configuración por defecto
     */
    public static boolean verify(License license, PublicKey publicKey) throws Exception {
        return verify(license, publicKey, defaultSignatureConfig);
    }

    /**
     * Verifica la firma de una licencia con configuración específica
     */
    public static boolean verify(License license, PublicKey publicKey, SignatureConfig config) {
        if (license == null || publicKey == null) {
            System.out.println("ERROR: Licencia o clave pública nula");
            return false;
        }

        if (license.getSignature() == null || license.getSignature().isEmpty()) {
            System.out.println("ERROR: La licencia no tiene firma digital");
            return false;
        }

        if (config == null) {
            config = defaultSignatureConfig;
        }

        String algorithm = license.getSignatureAlgorithm();
        if (algorithm == null || algorithm.isEmpty()) {
            algorithm = config.getAlgorithm();
            System.out.println("INFO: Usando algoritmo de firma por defecto: " + algorithm);
        }

        if (!isValidLicense(license)) {
            System.out.println("Licencia inválida: estructura básica incorrecta");
            return false;
        }

        boolean hardwareValid = verifyLicenseForHardware(license);
        if (!hardwareValid) {
            System.out.println("Verificación de Hardware completa fallida, probando con tolerancia...");
            boolean hardwareValidTolerance = verifyLicenseForHardwareWithTolerance(license);
            if (!hardwareValidTolerance) {
                System.err.println("Verificación de Hardware con tolerancia fallida");
                return false;
            }
        }

        try {
            String licenseData = serializeLicense(license);
            Signature signature = Signature.getInstance(algorithm, config.getProvider());
            signature.initVerify(publicKey);
            signature.update(licenseData.getBytes(StandardCharsets.UTF_8));

            byte[] sigBytes = Base64.getDecoder().decode(license.getSignature());
            return signature.verify(sigBytes);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException ex) {
            System.out.println("Error durante la verificación de la licencia: " + ex.getMessage());
            return false;
        }
    }

    /**
     * Verifica la firma de una licencia con algoritmo específico
     */
    public static boolean verify(License license, PublicKey publicKey, String signatureAlgorithm) {
        try {
            SignatureConfig config = new SignatureConfig();
            config.setAlgorithm(signatureAlgorithm);
            return verify(license, publicKey, config);
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * Verifica que la licencia sea válida para el hardware actual
     */
    public static boolean verifyLicenseForHardware(License license) {
        try {
            if (license.getHardwareId() != null && !license.getHardwareId().isEmpty()) {
                return HardwareId.matchesExactly(license.getHardwareId());
            }
            return true;
        } catch (Exception e) {
            System.out.println("Error al validar licencia para hardware: " + e.getMessage());
            return false;
        }
    }

    public static boolean verifyLicenseForHardwareWithTolerance(License license) {
        try {
            if (license.getHardwareId() != null && !license.getHardwareId().isEmpty()) {
                return HardwareId.matchesWithTolerance(license.getHardwareId());
            }
            return true;
        } catch (Exception e) {
            System.out.println("Error al validar licencia para hardware: " + e.getMessage());
            return false;
        }
    }

    /**
     * Calcula el fingerprint de una clave pública usando algoritmo por defecto
     */
    public static String calculatePublicKeyFingerprint(PublicKey publicKey) throws Exception {
        return calculatePublicKeyFingerprint(publicKey, defaultSignatureConfig.getHashAlgorithm());
    }

    /**
     * Calcula el fingerprint de una clave pública con algoritmo específico
     */
    public static String calculatePublicKeyFingerprint(PublicKey publicKey, String hashAlgorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        byte[] digest = md.digest(publicKey.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString().toUpperCase();
    }

    /**
     * Genera un par de claves RSA usando configuración por defecto
     */
    public static KeyPair generateKeyPair() throws Exception {
        return generateKeyPair(defaultSignatureConfig);
    }

    /**
     * Genera un par de claves RSA usando configuración específica
     */
    public static KeyPair generateKeyPair(SignatureConfig config) throws Exception {
        if (config == null) {
            config = defaultSignatureConfig;
        }

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM, config.getProvider());
        keyGen.initialize(config.getKeySize());
        return keyGen.generateKeyPair();
    }

    /**
     * Genera un par de claves RSA con algoritmo específico
     */
    public static KeyPair generateKeyPair(String algorithm, int keySize) throws Exception {
        SignatureConfig config = new SignatureConfig(algorithm, keySize);
        return generateKeyPair(config);
    }

    /**
     * Serializa una licencia a formato de texto
     */
    private static String serializeLicense(License license) {
        StringBuilder sb = new StringBuilder();
        sb.append("version=").append(license.getVersion() != null ? license.getVersion() : "").append("\n");
        sb.append("licenseeName=").append(license.getLicenseeName() != null ? license.getLicenseeName() : "").append("\n");
        sb.append("licenseeEmail=").append(license.getLicenseeEmail() != null ? license.getLicenseeEmail() : "").append("\n");
        sb.append("issueDate=").append(license.getIssueDate() != null ? license.getIssueDate().toString() : "").append("\n");
        sb.append("expirationDate=").append(license.getExpirationDate() != null ? license.getExpirationDate().toString() : "").append("\n");
        sb.append("productId=").append(license.getProductId() != null ? license.getProductId() : "").append("\n");
        sb.append("productVersion=").append(license.getProductVersion() != null ? license.getProductVersion() : "").append("\n");
        sb.append("licenseKey=").append(license.getLicenseKey() != null ? license.getLicenseKey() : "").append("\n");
        sb.append("isTrial=").append(license.isTrial()).append("\n");
        sb.append("maxUsers=").append(license.getMaxUsers()).append("\n");
        sb.append("features=").append(license.getFeaturesAsString()).append("\n");
        sb.append("licenseType=").append(license.getLicenseType() != null ? license.getLicenseType() : "").append("\n");
        sb.append("customData=").append(license.getCustomData() != null ? license.getCustomData() : "").append("\n");
        sb.append("hardwareId=").append(license.getHardwareId() != null ? license.getHardwareId() : "").append("\n");
        // No incluir firma ni algoritmo en la serialización para verificación
        return sb.toString();
    }

    /**
     * Método debug para comparar datos serializados para verificación de firma
     */
    public static void debugSignatureVerification(License license, PublicKey publicKey) throws Exception {
        debugSignatureVerification(license, publicKey, defaultSignatureConfig);
    }

    /**
     * Método debug para comparar datos serializados para verificación de firma
     * con configuración
     */
    public static void debugSignatureVerification(License license, PublicKey publicKey, SignatureConfig config) throws Exception {
        if (config == null) {
            config = defaultSignatureConfig;
        }

        String algorithm = license.getSignatureAlgorithm();
        if (algorithm == null || algorithm.isEmpty()) {
            algorithm = config.getAlgorithm();
            System.out.println("ADVERTENCIA: Algoritmo de firma era nulo, usando por defecto: " + algorithm);
        }

        if (license.getSignature() == null || license.getSignature().isEmpty()) {
            System.out.println("ERROR: La firma de la licencia es nula o vacía");
            return;
        }

        String licenseData = serializeLicense(license);
        System.out.println("Datos serializados para verificación:");
        System.out.println(licenseData);

        Signature signature = Signature.getInstance(algorithm, config.getProvider());
        signature.initVerify(publicKey);
        signature.update(licenseData.getBytes(StandardCharsets.UTF_8));

        byte[] sigBytes = Base64.getDecoder().decode(license.getSignature());
        boolean isValid = signature.verify(sigBytes);
        System.out.println("Firma válida: " + isValid);

        if (!isValid) {
            System.out.println("=== DEBUG: Comparando con firma original ===");
            System.out.println("Firma almacenada: " + license.getSignature());
        }
    }

    /**
     * Deserializa una licencia desde texto
     */
    private static License deserializeLicense(String licenseData) {
        License license = new License();
        String[] lines = licenseData.split("\n");

        for (String line : lines) {
            if (line.contains("=")) {
                String[] parts = line.split("=", 2);
                String key = parts[0];
                String value = parts.length > 1 ? parts[1] : "";

                switch (key) {
                    case "version":
                        license.setVersion(value);
                        break;
                    case "licenseeName":
                        license.setLicenseeName(value);
                        break;
                    case "licenseeEmail":
                        license.setLicenseeEmail(value);
                        break;
                    case "issueDate":
                        if (!value.isEmpty()) {
                            license.setIssueDate(LocalDateTime.parse(value));
                        }
                        break;
                    case "expirationDate":
                        if (!value.isEmpty()) {
                            license.setExpirationDate(LocalDateTime.parse(value));
                        }
                        break;
                    case "productId":
                        license.setProductId(value);
                        break;
                    case "productVersion":
                        license.setProductVersion(value);
                        break;
                    case "licenseKey":
                        license.setLicenseKey(value);
                        break;
                    case "isTrial":
                        license.setTrial(Boolean.parseBoolean(value));
                        break;
                    case "maxUsers":
                        if (!value.isEmpty()) {
                            license.setMaxUsers(Integer.parseInt(value));
                        }
                        break;
                    case "features":
                        license.setFeaturesFromString(value);
                        break;
                    case "licenseType":
                        license.setLicenseType(value);
                        break;
                    case "customData":
                        license.setCustomData(value);
                        break;
                    case "signatureAlgorithm":
                        license.setSignatureAlgorithm(value);
                        break;
                    case "signature":
                        license.setSignature(value);
                        break;
                    case "publicKeyFingerprint":
                        license.setPublicKeyFingerprint(value);
                        break;
                    case "hardwareId":
                        license.setHardwareId(value);
                        break;
                }
            }
        }
        return license;
    }

    /**
     * Encripta datos con clave pública RSA
     */
    public static byte[] encryptWithPublicKey(byte[] data, PublicKey publicKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * Desencripta datos con clave privada RSA
     */
    public static byte[] decryptWithPrivateKey(byte[] encryptedData, PrivateKey privateKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Carga una clave pública desde archivo
     */
    public static PublicKey loadPublicKeyFromFile(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    /**
     * Carga una clave privada desde archivo
     */
    public static PrivateKey loadPrivateKeyFromFile(String filePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }

    /**
     * Guarda una clave pública en archivo
     */
    public static void savePublicKeyToFile(PublicKey publicKey, String filePath)
            throws Exception {
        byte[] keyBytes = publicKey.getEncoded();
        Files.write(Paths.get(filePath), keyBytes);
    }

    /**
     * Guarda una clave privada en archivo
     */
    public static void savePrivateKeyToFile(PrivateKey privateKey, String filePath)
            throws Exception {
        byte[] keyBytes = privateKey.getEncoded();
        Files.write(Paths.get(filePath), keyBytes);
    }

    /**
     * Valida si una licencia es válida
     */
    public static boolean isValidLicense(License license) {
        if (license == null) {
            return false;
        }

        // Verificar fechas
        LocalDateTime now = LocalDateTime.now();
        if (license.getExpirationDate() != null && now.isAfter(license.getExpirationDate())) {
            return false;
        }

        // Verificar que el nombre del licenciatario no esté vacío
        if (license.getLicenseeName() == null || license.getLicenseeName().trim().isEmpty()) {
            return false;
        }

        // Verificar que la clave de licencia exista
        if (license.getLicenseKey() == null || license.getLicenseKey().trim().isEmpty()) {
            return false;
        }

        // Verificar que tenga un tipo de licencia válido
        if (license.getLicenseType() == null) {
            license.setLicenseType("UNKNOWN");
        }

        return true;
    }

    public static boolean isValidShortKey(String shortKey) {
        return ShortLicenseKey.isValidShortKey(shortKey);
    }

    public static boolean verifyShortKey(String shortKey, String seed) {
        return ShortLicenseKey.verifyShortKey(shortKey, seed);
    }

    public static boolean verifyShortKey(String shortKey, String secretKey, String value) {
        return ShortLicenseKey.verifyShortKey(shortKey, secretKey, value);
    }

    /**
     * Carga una licencia desde archivo en formato binario (por defecto)
     */
    public static License load(String filePath) throws Exception {
        return load(filePath, IOFormat.BINARY);
    }

    /**
     * Carga una licencia desde archivo en formato especificado
     */
    public static License load(String filePath, IOFormat format) throws Exception {
        byte[] fileContent = Files.readAllBytes(Paths.get(filePath));

        switch (format) {
            case BINARY:
                // Para formato binario, usamos ObjectInputStream
                try (ByteArrayInputStream bais = new ByteArrayInputStream(fileContent); ObjectInputStream ois = new ObjectInputStream(bais)) {
                    return (License) ois.readObject();
                }

            case BASE64:
                // Decodificar base64
                String base64Content = new String(fileContent, StandardCharsets.UTF_8);
                byte[] decodedBytes = Base64.getDecoder().decode(base64Content);
                try (ByteArrayInputStream bais = new ByteArrayInputStream(decodedBytes); ObjectInputStream ois = new ObjectInputStream(bais)) {
                    return (License) ois.readObject();
                }

            case STRING:
                // Para formato string, leemos directamente como string
                String stringContent = new String(fileContent, StandardCharsets.UTF_8);
                return deserializeLicense(stringContent);

            default:
                throw new IllegalArgumentException("Formato de entrada no soportado: " + format);
        }
    }

    /**
     * Guarda una licencia en archivo en formato binario (por defecto)
     */
    public static void save(License license, String filePath) throws Exception {
        save(license, filePath, IOFormat.BINARY);
    }

    /**
     * Guarda una licencia en archivo en formato especificado
     */
    public static void save(License license, String filePath, IOFormat format) throws Exception {
        Path path = Paths.get(filePath);
        if (path.getParent() != null) {
            Files.createDirectories(path.getParent());
        }
        switch (format) {
            case BINARY:
                // Guardar como objeto binario usando ObjectOutputStream
                try (FileOutputStream fos = new FileOutputStream(path.toFile()); ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                    oos.writeObject(license);
                }
                break;

            case BASE64:
                // Serializar a bytes, luego codificar en base64
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                    oos.writeObject(license);
                }
                byte[] serializedBytes = baos.toByteArray();
                String base64Content = Base64.getEncoder().encodeToString(serializedBytes);
                Files.write(path, base64Content.getBytes(StandardCharsets.UTF_8), StandardOpenOption.TRUNCATE_EXISTING);
                break;

            case STRING:
                // Guardar como texto serializado
                String content = serializeLicenseWithMetadata(license);
                Files.write(path, content.getBytes(StandardCharsets.UTF_8), StandardOpenOption.TRUNCATE_EXISTING);
                break;

            default:
                throw new IllegalArgumentException("Formato de salida no soportado: " + format);
        }
    }

    /**
     * Serializa una licencia con metadatos completos
     */
    public static String serializeLicenseWithMetadata(License license) {
        return LicenseSerializer.serializeLicenseWithMetadata(license);
    }

    /**
     * Genera una clave de licencia única
     */
    public static String generateLicenseId() {
        return java.util.UUID.randomUUID().toString().replace("-", "").toUpperCase();
    }

    /**
     * Genera una clave de licencia basada en parámetros
     */
    public static String generateLicenseId(String productId, String licensee, long timestamp) {
        String baseString = productId + licensee + timestamp + System.currentTimeMillis();
        return Base64.getEncoder().encodeToString(baseString.getBytes()).substring(0, 20).toUpperCase();
    }

    /**
     * Genera una clave corta en formato DCWI3U-6RDTB8-EBMPTJ-TVURQ7
     */
    public static String generateShortKey(String seed) {
        return ShortLicenseKey.generateShortKey(seed);
    }

    /**
     * Genera una clave corta a partir de una semilla
     */
    public static String createShortLicenseKey(String seed) {
        return ShortLicenseKey.generateShortKey(seed);
    }

    /**
     * Genera una clave corta a partir de una clave secreta y valor
     */
    public static String createShortLicenseKey(String secretKey, String value) {
        String combined = secretKey + ":" + value;
        return ShortLicenseKey.generateShortKey(combined);
    }

    /**
     * Genera una semilla a partir de múltiples datos
     *
     * @param data Array de strings para generar la semilla
     * @return Semilla generada como string
     */
    public static String generateSeed(String... data) {
        return SeedGenerator.generateSeed(data);
    }

    public static String generatePrefixSeed(String prefix, String... data) {
        return SeedGenerator.generateSeed(prefix, data);
    }

    /**
     * Obtiene el ID de hardware usando una estrategia más consistente
     */
    public static String getHardwareId() {
        if (hardwareIdCache != null) {
            return hardwareIdCache;
        }

        hardwareIdCache = HardwareId.generateFingerprint();
        return hardwareIdCache;
    }

    public static void setHardwareTolerance(int tolerance) {
        HardwareId.setTolerance(tolerance);
    }

    /**
     * Crea una licencia de prueba (trial) con hardware ID
     */
    public static License createTrialLicense(String licenseeName, String licenseeEmail,
            String productId, String productVersion,
            int days) {
        License license = new License();
        license.setLicenseeName(licenseeName);
        license.setLicenseeEmail(licenseeEmail);
        license.setProductId(productId);
        license.setProductVersion(productVersion);
        license.setLicenseKey(generateLicenseId());
        license.setTrial(true);
        license.setExpirationDate(LocalDateTime.now()
                .plusDays(days)
                .withHour(23)
                .withMinute(59)
                .withSecond(59));
        license.setLicenseType("TRIAL");
        license.setHardwareId(getHardwareId());
        return license;
    }

    /**
     * Crea una licencia comercial con hardware ID
     */
    public static License createCommercialLicense(String licenseeName, String licenseeEmail,
            String productId, String productVersion,
            LocalDateTime expirationDate, int maxUsers) {
        License license = new License();
        license.setLicenseeName(licenseeName);
        license.setLicenseeEmail(licenseeEmail);
        license.setProductId(productId);
        license.setProductVersion(productVersion);
        license.setLicenseKey(generateLicenseId());
        license.setTrial(false);
        license.setExpirationDate(expirationDate);
        license.setMaxUsers(maxUsers);
        license.setLicenseType("COMMERCIAL");
        license.setHardwareId(getHardwareId());
        return license;
    }

    /**
     * Crea una licencia comercial sin restricción de hardware (para licencias
     * multiplataforma)
     */
    public static License createPortableLicense(String licenseeName, String licenseeEmail,
            String productId, String productVersion,
            LocalDateTime expirationDate, int maxUsers) {
        License license = new License();
        license.setLicenseeName(licenseeName);
        license.setLicenseeEmail(licenseeEmail);
        license.setProductId(productId);
        license.setProductVersion(productVersion);
        license.setLicenseKey(generateLicenseId());
        license.setTrial(false);
        license.setExpirationDate(expirationDate);
        license.setMaxUsers(maxUsers);
        license.setLicenseType("PORTABLE");
        return license;
    }

    /**
     * API Fluida para crear licencias
     */
    public static LicenseBuilder license() {
        return new LicenseBuilder();
    }

    /**
     * API Fluida para crear licencias de prueba
     */
    public static LicenseBuilder trialLicense() {
        return new LicenseBuilder()
                .trial(true)
                .licenseType("TRIAL");
    }

    /**
     * API Fluida para crear licencias comerciales
     */
    public static LicenseBuilder commercialLicense() {
        return new LicenseBuilder()
                .trial(false)
                .licenseType("COMMERCIAL");
    }

    public static boolean isExpired(License license) {
        return DateTimeUtils.isExpired(license.getExpirationDate());
    }

    public static long getRemainingTimeMillis(Date expirationDate) {
        return DateTimeUtils.getRemainingTimeMillis(expirationDate);
    }

    public static long getRemainingTimeMillis(LocalDateTime expirationDate) {
        return DateTimeUtils.getRemainingTimeMillis(expirationDate);
    }

    public static long getRemainingDays(Date expirationDate) {
        return DateTimeUtils.getRemainingDays(expirationDate);
    }

    public static long getRemainingDays(LocalDateTime expirationDate) {
        return DateTimeUtils.getRemainingDays(expirationDate);
    }

    public static long getRemainingHours(Date expirationDate) {
        return DateTimeUtils.getRemainingHours(expirationDate);
    }

    public static long getRemainingHours(LocalDateTime expirationDate) {
        return DateTimeUtils.getRemainingHours(expirationDate);
    }

    public static long getRemainingMinutes(Date expirationDate) {
        return DateTimeUtils.getRemainingMinutes(expirationDate);
    }

    public static String getExpirationStatus(Date expirationDate) {
        return DateTimeUtils.getExpirationStatus(expirationDate);
    }

    public static String getExpirationStatus(LocalDateTime expirationDate) {
        return DateTimeUtils.getExpirationStatus(expirationDate);
    }

    public static String getFormattedRemainingTime(Date expirationDate) {
        return DateTimeUtils.getFormattedRemainingTime(expirationDate);
    }

    public static String getFormattedRemainingTime(LocalDateTime expirationDate) {
        return DateTimeUtils.getFormattedRemainingTime(expirationDate);
    }

    public static LocalDateTime createExpirationDate(int days) {
        return DateTimeUtils.createExpirationDate(days);
    }

    public static LocalDateTime createExpirationDate(int days, int hours, int minutes) {
        return DateTimeUtils.createExpirationDate(days, hours, minutes);
    }

    public static void revoke(License license) {
        revocationManager.revokeLicense(license.toString());
    }

    public static boolean isRevoke(License license) {
        return revocationManager.isRevoked(license.toString());
    }

    public static Set<String> getRevokedLicenses() {
        return revocationManager.getRevokedLicenses();
    }

}
