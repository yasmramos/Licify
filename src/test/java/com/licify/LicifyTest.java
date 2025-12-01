package com.licify;

import com.licify.Licify.License;
import com.licify.core.LicenseRevocationManager;
import com.licify.io.IOFormat;
import com.licify.signing.SignatureConfig;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class LicifyTest {

    private static final String TEST_LICENSE_FILE = "test_license.bin";
    private static final String TEST_PUBLIC_KEY_FILE = "test_public_key.der";
    private static final String TEST_PRIVATE_KEY_FILE = "test_private_key.der";
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private KeyPair testKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        
        SignatureConfig defaultConfig = new SignatureConfig();
        Licify.setDefaultSignatureConfig(defaultConfig);
        
        LicenseRevocationManager manager = LicenseRevocationManager.getInstance();
        manager.clearAllRevocations();
        
        // Generar claves de prueba
        testKeyPair = Licify.generateKeyPair();
        privateKey = testKeyPair.getPrivate();
        publicKey = testKeyPair.getPublic();
        
        // Limpiar archivos de prueba
        deleteTestFiles();
    }

    @AfterEach
    void tearDown() {
        deleteTestFiles();
    }

    private void deleteTestFiles() {
        deleteFile(TEST_LICENSE_FILE);
        deleteFile(TEST_PUBLIC_KEY_FILE);
        deleteFile(TEST_PRIVATE_KEY_FILE);
    }

    private void deleteFile(String fileName) {
        try {
            Files.deleteIfExists(Paths.get(fileName));
        } catch (IOException ignored) {}
    }

    @Test
    @DisplayName("Generación de claves RSA")
    void testGenerateKeyPair() throws Exception {
        KeyPair keyPair = Licify.generateKeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        assertEquals("RSA", keyPair.getPrivate().getAlgorithm());
        assertEquals("RSA", keyPair.getPublic().getAlgorithm());
    }

    @Test
    @DisplayName("Generación de claves con configuración específica")
    void testGenerateKeyPairWithConfig() throws Exception {
        SignatureConfig config = new SignatureConfig("SHA256withRSA", 2048);
        KeyPair keyPair = Licify.generateKeyPair(config);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    @Test
    @DisplayName("Generación de semillas")
    void testGenerateSeed() {
        // Test con un solo dato
        String seed1 = Licify.generateSeed("USUARIO123");
        assertEquals("USUARIO123", seed1);

        // Test con múltiples datos
        String seed2 = Licify.generateSeed("USUARIO123", "PRODUCTO001", "2025");
        assertEquals("USUARIO123:PRODUCTO001:2025", seed2);

        // Test con varios datos
        String seed3 = Licify.generateSeed("EMPRESA_S.A.", "CLIENTE_001", "SUBSCRIPTOR", "2025");
        assertEquals("EMPRESA_S.A.:CLIENTE_001:SUBSCRIPTOR:2025", seed3);

        // Test con null
        String seed4 = Licify.generateSeed((String[]) null);
        assertNotNull(seed4);
        assertTrue(seed4.startsWith("DEFAULT_SEED_"));
    }

    @Test
    @DisplayName("Generación de claves cortas")
    void testGenerateShortKey() {
        String seed = "TEST_SEED_123";
        String shortKey = Licify.createShortLicenseKey(seed);
        
        // Verificar formato correcto
        assertTrue(Licify.isValidShortKey(shortKey));
        assertEquals(4, shortKey.split("-").length);
        assertEquals(6, shortKey.split("-")[0].length());
        
        // Verificar consistencia
        String shortKey2 = Licify.createShortLicenseKey(seed);
        assertEquals(shortKey, shortKey2);
    }

    @Test
    @DisplayName("Verificación de claves cortas")
    void testVerifyShortKey() {
        String seed = "VERIFICATION_TEST";
        String shortKey = Licify.createShortLicenseKey(seed);
        
        // Verificación exitosa
        assertTrue(Licify.verifyShortKey(shortKey, seed));
        
        // Verificación fallida con semilla incorrecta
        assertFalse(Licify.verifyShortKey(shortKey, "WRONG_SEED"));
        
        // Verificación con clave secreta y valor
        String secretKey = "SECRET_KEY";
        String value = "TEST_VALUE";
        String shortKey2 = Licify.createShortLicenseKey(secretKey, value);
        assertTrue(Licify.verifyShortKey(shortKey2, secretKey, value));
        assertFalse(Licify.verifyShortKey(shortKey2, "WRONG_SECRET", value));
    }

    @Test
    @DisplayName("Creación de licencia comercial")
    void testCreateCommercialLicense() {
        LocalDateTime expirationDate = LocalDateTime.now().plusDays(365);
        
        License license = Licify.createCommercialLicense(
            "Empresa S.A.",
            "contacto@empresa.com",
            "PROD-001",
            "2.0",
            expirationDate,
            100
        );
        
        assertNotNull(license);
        assertEquals("Empresa S.A.", license.getLicenseeName());
        assertEquals("contacto@empresa.com", license.getLicenseeEmail());
        assertEquals("PROD-001", license.getProductId());
        assertEquals("2.0", license.getProductVersion());
        assertEquals(100, license.getMaxUsers());
        assertTrue(license.getLicenseKey() != null && !license.getLicenseKey().isEmpty());
        assertFalse(license.isTrial());
        assertEquals("COMMERCIAL", license.getLicenseType());
        assertNotNull(license.getHardwareId());
        assertEquals(expirationDate, license.getExpirationDate());
    }

    @Test
    @DisplayName("Creación de licencia de prueba")
    void testCreateTrialLicense() {
        License license = Licify.createTrialLicense(
            "Usuario de Prueba",
            "prueba@test.com",
            "PROD-001",
            "1.0",
            30
        );
        
        assertNotNull(license);
        assertEquals("Usuario de Prueba", license.getLicenseeName());
        assertEquals("prueba@test.com", license.getLicenseeEmail());
        assertEquals("PROD-001", license.getProductId());
        assertEquals("1.0", license.getProductVersion());
        assertTrue(license.isTrial());
        assertEquals("TRIAL", license.getLicenseType());
        assertNotNull(license.getHardwareId());
        assertTrue(license.getExpirationDate().isAfter(LocalDateTime.now()));
    }

    @Test
    @DisplayName("Creación de licencia portable")
    void testCreatePortableLicense() {
        LocalDateTime expirationDate = LocalDateTime.now().plusDays(365);
        
        License license = Licify.createPortableLicense(
            "Usuario Portable",
            "portable@usuario.com",
            "PROD-002",
            "1.5",
            expirationDate,
            5
        );
        
        assertNotNull(license);
        assertEquals("Usuario Portable", license.getLicenseeName());
        assertEquals("portable@usuario.com", license.getLicenseeEmail());
        assertEquals("PROD-002", license.getProductId());
        assertEquals("1.5", license.getProductVersion());
        assertEquals(5, license.getMaxUsers());
        assertFalse(license.isTrial());
        assertEquals("PORTABLE", license.getLicenseType());
        assertNull(license.getHardwareId()); // No debería tener hardware ID
        assertEquals(expirationDate, license.getExpirationDate());
    }

    @Test
    @DisplayName("API Fluida - Builder Pattern")
    void testLicenseBuilder() {
        License license = Licify.license()
            .licenseeName("Empresa S.A.")
            .licenseeEmail("contacto@empresa.com")
            .productId("PROD-001")
            .productVersion("2.0")
            .expirationDate(LocalDateTime.now().plusDays(365))
            .maxUsers(100)
            .feature("REPORTING")
            .feature("EXPORT")
            .licenseType("COMMERCIAL")
            .build();
        
        assertNotNull(license);
        assertEquals("Empresa S.A.", license.getLicenseeName());
        assertEquals("contacto@empresa.com", license.getLicenseeEmail());
        assertEquals("PROD-001", license.getProductId());
        assertEquals("2.0", license.getProductVersion());
        assertEquals(100, license.getMaxUsers());
        assertTrue(license.hasFeature("REPORTING"));
        assertTrue(license.hasFeature("EXPORT"));
        assertEquals("COMMERCIAL", license.getLicenseType());
    }

    @Test
    @DisplayName("Firmado de licencia")
    void testSignLicense() throws Exception {
        License license = Licify.createCommercialLicense(
            "Empresa S.A.",
            "contacto@empresa.com",
            "PROD-001",
            "2.0",
            LocalDateTime.now().plusDays(365),
            100
        );
        
        // Firmar licencia
        License signedLicense = Licify.sign(license, privateKey, publicKey);
        
        assertNotNull(signedLicense.getSignature());
        assertNotNull(signedLicense.getSignatureAlgorithm());
        assertNotNull(signedLicense.getPublicKeyFingerprint());
        assertTrue(signedLicense.getSignature().length() > 0);
    }

    @Test
    @DisplayName("Verificación de licencia firmada")
    void testVerifySignedLicense() throws Exception {
        License license = Licify.createCommercialLicense(
            "Empresa S.A.",
            "contacto@empresa.com",
            "PROD-001",
            "2.0",
            LocalDateTime.now().plusDays(365),
            100
        );
        
        // Firmar licencia
        License signedLicense = Licify.sign(license, privateKey, publicKey);
        
        // Verificar firma
        boolean isValid = Licify.verify(signedLicense, publicKey);
        assertTrue(isValid);
    }

    @Test
    @DisplayName("Verificación de licencia inválida")
    void testVerifyInvalidLicense() throws Exception {
        License license = Licify.createCommercialLicense(
            "Empresa S.A.",
            "contacto@empresa.com",
            "PROD-001",
            "2.0",
            LocalDateTime.now().plusDays(365),
            100
        );
        
        // Verificar firma con clave incorrecta
        KeyPair wrongKeyPair = Licify.generateKeyPair();
        boolean isValid = Licify.verify(license, wrongKeyPair.getPublic());
        assertFalse(isValid);
    }

    @Test
    @DisplayName("Guardado y carga de licencia binaria")
    void testSaveAndLoadBinary() throws Exception {
        License license = Licify.createCommercialLicense(
            "Empresa S.A.",
            "contacto@empresa.com",
            "PROD-001",
            "2.0",
            LocalDateTime.now().plusDays(365),
            100
        );
        
        // Firmar licencia
        License signedLicense = Licify.sign(license, privateKey, publicKey);
        
        // Guardar licencia
        Licify.save(signedLicense, TEST_LICENSE_FILE, IOFormat.BINARY);
        
        // Cargar licencia
        License loadedLicense = Licify.load(TEST_LICENSE_FILE, IOFormat.BINARY);
        
        // Verificar que los datos sean iguales
        assertEquals(signedLicense.getLicenseeName(), loadedLicense.getLicenseeName());
        assertEquals(signedLicense.getLicenseKey(), loadedLicense.getLicenseKey());
        assertEquals(signedLicense.getSignature(), loadedLicense.getSignature());
        assertEquals(signedLicense.getSignatureAlgorithm(), loadedLicense.getSignatureAlgorithm());
    }

    @Test
    @DisplayName("Guardado y carga de licencia en formato string")
    void testSaveAndLoadString() throws Exception {
        License license = Licify.createCommercialLicense(
            "Empresa S.A.",
            "contacto@empresa.com",
            "PROD-001",
            "2.0",
            LocalDateTime.now().plusDays(365),
            100
        );
        
        // Firmar licencia
        License signedLicense = Licify.sign(license, privateKey, publicKey);
        
        // Guardar licencia en formato string
        Licify.save(signedLicense, TEST_LICENSE_FILE, IOFormat.STRING);
        
        // Cargar licencia
        License loadedLicense = Licify.load(TEST_LICENSE_FILE, IOFormat.STRING);
        
        // Verificar que los datos sean iguales
        assertEquals(signedLicense.getLicenseeName(), loadedLicense.getLicenseeName());
        assertEquals(signedLicense.getLicenseKey(), loadedLicense.getLicenseKey());
        assertEquals(signedLicense.getSignature(), loadedLicense.getSignature());
        assertEquals(signedLicense.getSignatureAlgorithm(), loadedLicense.getSignatureAlgorithm());
    }

    @Test
    @DisplayName("Validación de formato de clave corta")
    void testValidShortKeyFormat() {
        // Formato válido
        String validKey = "ABC123-DEF456-GHI789-JKL012";
        assertTrue(Licify.isValidShortKey(validKey));
        
        // Formato inválido - mal formateado
        String invalidKey1 = "ABC123-DEF456-GHI789"; // Solo 3 segmentos
        assertFalse(Licify.isValidShortKey(invalidKey1));
        
        // Formato inválido - segmento incorrecto
        String invalidKey2 = "ABC1234-DEF456-GHI789-JKL012"; // Segmento de 7 caracteres
        assertFalse(Licify.isValidShortKey(invalidKey2));
        
        // Formato inválido - contiene caracteres no válidos
        String invalidKey3 = "ABC123-DEF456-GHI789-JKL01!"; // Carácter especial
        assertFalse(Licify.isValidShortKey(invalidKey3));
    }

    @Test
    @DisplayName("Generación de ID de licencia única")
    void testGenerateLicenseId() {
        String id1 = Licify.generateLicenseId();
        String id2 = Licify.generateLicenseId();
        
        assertNotNull(id1);
        assertNotNull(id2);
        assertTrue(id1.length() > 0);
        assertTrue(id2.length() > 0);
        assertNotEquals(id1, id2); // Deben ser diferentes
    }

    @Test
    @DisplayName("Manejo de features en licencia")
    void testLicenseFeatures() {
        License license = Licify.license()
            .feature("FEATURE_A")
            .feature("FEATURE_B")
            .feature("FEATURE_C")
            .build();
        
        assertTrue(license.hasFeature("FEATURE_A"));
        assertTrue(license.hasFeature("FEATURE_B"));
        assertTrue(license.hasFeature("FEATURE_C"));
        assertFalse(license.hasFeature("FEATURE_D"));
        
        // Remover feature
        license.removeFeature("FEATURE_B");
        assertFalse(license.hasFeature("FEATURE_B"));
        assertTrue(license.hasFeature("FEATURE_A"));
        assertTrue(license.hasFeature("FEATURE_C"));
        
        // Limpiar todas las features
        license.clearFeatures();
        assertFalse(license.hasFeature("FEATURE_A"));
        assertFalse(license.hasFeature("FEATURE_C"));
    }

    @Test
    @DisplayName("Verificación de revocación de licencia")
    void testLicenseRevocation() {
        License license = Licify.createCommercialLicense(
            "Empresa S.A.",
            "contacto@empresa.com",
            "PROD-001",
            "2.0",
            LocalDateTime.now().plusDays(365),
            100
        );
        
        // Inicialmente no revocada
        assertFalse(Licify.isRevoke(license));
        
        // Revocar licencia
        Licify.revoke(license);
        
        // Verificar que esté revocada
        assertTrue(Licify.isRevoke(license));
        
        // Verificar lista de licencias revocadas
        Set<String> revoked = Licify.getRevokedLicenses();
        assertFalse(revoked.isEmpty());
    }

    @Test
    @DisplayName("Validación de licencia básica")
    void testIsValidLicense() {
        // Licencia válida
        License validLicense = Licify.createCommercialLicense(
            "Empresa S.A.",
            "contacto@empresa.com",
            "PROD-001",
            "2.0",
            LocalDateTime.now().plusDays(365),
            100
        );
        
        assertTrue(Licify.isValidLicense(validLicense));
        
        // Licencia inválida - sin nombre
        License invalidLicense = new License();
        invalidLicense.setLicenseKey("TEST_KEY");
        assertFalse(Licify.isValidLicense(invalidLicense));
        
        // Licencia inválida - sin clave
        License invalidLicense2 = new License();
        invalidLicense2.setLicenseeName("Empresa S.A.");
        assertFalse(Licify.isValidLicense(invalidLicense2));
    }

    @Test
    @DisplayName("Manejo de tiempo de expiración")
    void testExpirationTime() {
        LocalDateTime futureDate = LocalDateTime.now().plusDays(30);
        LocalDateTime pastDate = LocalDateTime.now().minusDays(1);
        
        // Fecha futura (no expirada)
        assertFalse(Licify.isExpired(new Licify.License() {{
            setExpirationDate(futureDate);
        }}));
        
        // Fecha pasada (expirada)
        assertTrue(Licify.isExpired(new Licify.License() {{
            setExpirationDate(pastDate);
        }}));
    }

    @Test
    @DisplayName("Generación de fingerprint de clave pública")
    void testCalculatePublicKeyFingerprint() throws Exception {
        String fingerprint = Licify.calculatePublicKeyFingerprint(publicKey);
        assertNotNull(fingerprint);
        assertTrue(fingerprint.length() > 0);
        assertTrue(fingerprint.matches("[0-9A-F]+")); // Solo hexadecimal
    }

    @Test
    @DisplayName("Configuración por defecto de firma")
    void testDefaultSignatureConfig() {
        SignatureConfig config = Licify.getDefaultSignatureConfig();
        assertNotNull(config);
        assertEquals("SHA256withRSA", config.getAlgorithm());
        assertEquals(2048, config.getKeySize());
    }

    @Test
    @DisplayName("Establecimiento de configuración por defecto")
    void testSetDefaultSignatureConfig() {
        SignatureConfig newConfig = new SignatureConfig("SHA512withRSA", 4096);
        Licify.setDefaultSignatureConfig(newConfig);
        
        SignatureConfig retrievedConfig = Licify.getDefaultSignatureConfig();
        assertEquals("SHA512withRSA", retrievedConfig.getAlgorithm());
        assertEquals(4096, retrievedConfig.getKeySize());
    }

    @Test
    @DisplayName("Serialización y deserialización de licencia")
    void testSerializeDeserialize() {
        License originalLicense = Licify.createCommercialLicense(
            "Empresa S.A.",
            "contacto@empresa.com",
            "PROD-001",
            "2.0",
            LocalDateTime.now().plusDays(365),
            100
        );
        
        // Serializar
        String serialized = Licify.serializeLicenseWithMetadata(originalLicense);
        assertNotNull(serialized);
        assertTrue(serialized.contains("licenseeName=Empresa S.A."));
        
        // Deserializar (simulación)
        // La deserialización se prueba en otros tests con carga de archivos
    }

    @Test
    @DisplayName("Funciones de utilidad de fecha y tiempo")
    void testDateTimeUtils() {
        LocalDateTime futureDate = LocalDateTime.now().plusDays(30);
        LocalDateTime pastDate = LocalDateTime.now().minusDays(1);
        
        // Test remaining time functions
        long remainingDays = Licify.getRemainingDays(futureDate);
        assertTrue(remainingDays > 0);
        
        long remainingHours = Licify.getRemainingHours(futureDate);
        assertTrue(remainingHours > 0);
        
        // Test expired date
        assertTrue(Licify.isExpired(new License() {{
            setExpirationDate(pastDate);
        }}));
        
        // Test creation of expiration date
        LocalDateTime createdDate = Licify.createExpirationDate(30);
        assertNotNull(createdDate);
        assertTrue(createdDate.isAfter(LocalDateTime.now()));
    }

    @Test
    @DisplayName("Verificación de licencia con configuración específica")
    void testVerifyWithSpecificConfig() throws Exception {
        License license = Licify.createCommercialLicense(
            "Empresa S.A.",
            "contacto@empresa.com",
            "PROD-001",
            "2.0",
            LocalDateTime.now().plusDays(365),
            100
        );
        
        // Firmar con configuración específica
        SignatureConfig config = new SignatureConfig("SHA256withRSA", 2048);
        License signedLicense = Licify.sign(license, privateKey, publicKey, config);
        
        // Verificar con misma configuración
        boolean isValid = Licify.verify(signedLicense, publicKey, config);
        assertTrue(isValid);
    }

    @Test
    @DisplayName("Prueba de firma con algoritmo específico")
    void testVerifyWithSpecificAlgorithm() throws Exception {
        License license = Licify.createCommercialLicense(
            "Empresa S.A.",
            "contacto@empresa.com",
            "PROD-001",
            "2.0",
            LocalDateTime.now().plusDays(365),
            100
        );
        
        // Firmar licencia
        License signedLicense = Licify.sign(license, privateKey, publicKey);
        
        // Verificar con algoritmo específico
        boolean isValid = Licify.verify(signedLicense, publicKey, "SHA256withRSA");
        assertTrue(isValid);
    }
}