# Licify - Java License Management Library 2.0

[![Java CI with Maven](https://github.com/yasmramos/Licify/actions/workflows/maven.yml/badge.svg)](https://github.com/yasmramos/Licify/actions/workflows/maven.yml)
[![Maven Central](https://img.shields.io/badge/Maven%20Central-2.0.0-blue.svg)](https://central.sonatype.com/artifact/com.licify/licify)
[![Java Version](https://img.shields.io/badge/Java-17%2B-green.svg)](https://adoptium.net/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📖 Descripción

**Licify** es una biblioteca Java robusta y moderna para la gestión de licencias de software, que proporciona funcionalidades avanzadas de encriptación híbrida (AES+RSA), firmas digitales, validación de hardware y múltiples formatos de serialización.

### ✨ Novedades en la Versión 2.0

- ✅ **Java 17+:** Actualizado a las últimas características del lenguaje
- ✅ **CI/CD Completo:** GitHub Actions con builds multi-versión (Java 17 y 21)
- ✅ **Publicación Automática:** Configurado para Maven Central
- ✅ **Mejor Documentación:** Javadocs completos y ejemplos detallados
- ✅ **Nuevas Funcionalidades:** Licencias flotantes, sistema de actualización automática
- ✅ **Calidad de Código:** Checkstyle, JaCoCo coverage >40%

## 🚀 Características Principales

### 🔒 Encriptación Híbrida
- Combinación de algoritmos simétricos (AES-256) y asimétricos (RSA-2048/3072/4096)
- Configuración flexible de parámetros de seguridad
- Soporte para múltiples tamaños de clave
- Gestión segura de claves de sesión

### ✍️ Firmas Digitales
- Validación criptográfica de integridad
- Algoritmos configurables (SHA256withRSA, SHA384withRSA, SHA512withRSA)
- Verificación automática de autenticidad
- Huella digital de clave pública

### 🖥️ Identificación de Hardware
- Vinculación de licencias a hardware específico
- Análisis de múltiples componentes (CPU, motherboard, disco, MAC)
- Backup de configuración de hardware
- Tolerancia a cambios menores de hardware

### 📝 Múltiples Formatos
- **BINARY:** Máxima eficiencia y compactación
- **STRING:** Legibilidad humana (Base64)
- **XML:** Interoperabilidad con sistemas externos
- **PROPERTIES:** Integración con archivos de configuración

### 🔄 Sistema de Revocación
- Lista negra de licencias revocadas
- Persistencia en archivo JSON
- Verificación en tiempo real
- Limpieza programada

### 🎯 Generación de Seeds
- Seeds criptográficos determinísticos
- Múltiples algoritmos hash (SHA-256/384/512)
- Entropía del sistema incluida
- Ideal para licencias offline

## 📦 Instalación

### Maven

```xml
<dependency>
    <groupId>com.licify</groupId>
    <artifactId>licify</artifactId>
    <version>2.0.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'com.licify:licify:2.0.0'
```

### Requisitos Previos
- **Java:** 17 o superior
- **Maven:** 3.8+ (para construcción)

## ⚡ Inicio Rápido

### 1. Generar Par de Claves

```java
import com.licify.LicenseKeyPair;
import java.security.KeyPair;

// Generar par de claves RSA
KeyPair keyPair = LicenseKeyPair.generateKeyPair(2048);

// Guardar claves
LicenseKeyPair.saveKeyPair(keyPair, "keys/");
```

### 2. Crear una Licencia

```java
import com.licify.Licify;
import com.licify.Licify.License;
import java.time.LocalDateTime;

Licify licify = new Licify();

License license = new Licify.LicenseBuilder()
    .licenseeName("Juan Pérez")
    .licenseeEmail("juan@example.com")
    .productId("MYPRODUCT-001")
    .productVersion("1.0.0")
    .expirationDate(LocalDateTime.now().plusYears(1))
    .maxUsers(10)
    .feature("premium-support")
    .feature("cloud-sync")
    .licenseType("COMMERCIAL")
    .hardwareId()  // Usa el hardware actual
    .build();
```

### 3. Firmar la Licencia

```java
import java.security.KeyPair;

// Cargar clave privada
KeyPair keyPair = LicenseKeyPair.loadKeyPair("keys/");

// Firmar licencia
licify.sign(license, keyPair);

System.out.println("Licencia firmada: " + license.getSignature());
```

### 4. Guardar Licencia

```java
import com.licify.io.IOFormat;

// Guardar en formato binario
licify.save(license, "license.bin", IOFormat.BINARY);

// O guardar en formato XML
licify.save(license, "license.xml", IOFormat.XML);
```

### 5. Cargar y Validar Licencia

```java
import com.licify.Licify.ValidationResult;

// Cargar licencia
License loadedLicense = licify.load("license.bin", IOFormat.BINARY);

// Validar firma
ValidationResult result = licify.validateSignature(loadedLicense, keyPair.getPublic());
if (result.isValid()) {
    System.out.println("✅ Licencia válida");
} else {
    System.err.println("❌ Licencia inválida: " + result.getErrors());
}

// Verificar expiración
if (loadedLicense.isExpired()) {
    System.err.println("⚠️ Licencia expirada");
}

// Verificar hardware
boolean hardwareMatch = licify.validateHardwareId(loadedLicense);
if (!hardwareMatch) {
    System.err.println("⚠️ Hardware no coincide");
}
```

## 🔧 Configuración Avanzada

### Configurar Encriptación Personalizada

```java
import com.licify.encryption.EncryptionConfig;

EncryptionConfig config = new EncryptionConfig.Builder()
    .setKeySize(4096)           // RSA 4096 bits
    .setAesKeySize(256)         // AES 256 bits
    .setTransformation("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    .build();

licify.setDefaultEncryptionConfig(config);
```

### Configurar Firma Digital

```java
import com.licify.signing.SignatureConfig;

SignatureConfig sigConfig = new SignatureConfig.Builder()
    .algorithm("SHA512withRSA")
    .provider("SunRsaSign")
    .hashAlgorithm("SHA-512")
    .build();

licify.setDefaultSignatureConfig(sigConfig);
```

### Licencias Flotantes (Network)

```java
// Crear licencia flotante para red
License floatingLicense = new Licify.LicenseBuilder()
    .licenseeName("Empresa S.A.")
    .productId("NETWORK-LICENSE")
    .maxUsers(50)  // 50 usuarios concurrentes
    .licenseType("FLOATING")
    .customData("{\"server\":\"license-server.example.com\",\"port\":27000}")
    .build();
```

## 🧪 Ejecución de Tests

```bash
# Compilar proyecto
mvn clean compile

# Ejecutar tests
mvn test

# Generar reporte de cobertura
mvn jacoco:report

# Verificar calidad de código
mvn verify

# Build completo
mvn clean install
```

Los reportes se generan en:
- `target/surefire-reports/` - Resultados de tests
- `target/site/jacoco/` - Cobertura de código HTML
- `target/jacoco.exec` - Datos de ejecución

## 📊 Estructura del Proyecto

```
Licify/
├── src/main/java/com/licify/
│   ├── Licify.java              # API principal
│   ├── LicenseKeyPair.java      # Gestión de claves
│   ├── SeedGenerator.java       # Generación de seeds
│   ├── Main.java                # Punto de entrada
│   ├── core/                    # Funcionalidades core
│   │   ├── LicenseSerializer.java
│   │   ├── LicenseRevocationManager.java
│   │   └── ShortLicenseKey.java
│   ├── encryption/              # Encriptación híbrida
│   │   ├── HybridEncryption.java
│   │   ├── EncryptionConfig.java
│   │   └── HybridEncryptionResult.java
│   ├── signing/                 # Firmas digitales
│   │   ├── DigitalSignature.java
│   │   └── SignatureConfig.java
│   ├── hardware/                # Identificación HW
│   │   ├── HardwareId.java
│   │   └── HardwareIdBackup.java
│   ├── io/                      # Formatos I/O
│   │   └── IOFormat.java
│   ├── util/                    # Utilidades
│   │   ├── KeyUtils.java
│   │   └── DateTimeUtils.java
│   └── exception/               # Excepciones
│       └── ValidationException.java
├── src/test/java/com/licify/
│   └── LicifyTest.java          # Suite de tests
├── .github/workflows/
│   └── maven.yml                # CI/CD pipeline
├── pom.xml                      # Configuración Maven
└── README.md                    # Esta documentación
```

## 🏗️ CI/CD Pipeline

El proyecto incluye un pipeline completo de GitHub Actions que:

1. **Build Multi-Versión:** Compila con Java 17 y 21
2. **Tests Automatizados:** Ejecuta 27 tests unitarios
3. **Cobertura:** Genera reportes JaCoCo
4. **Calidad:** Ejecuta Checkstyle y Javadoc
5. **Publicación:** Despliega a Maven Central en releases

### Secrets Requeridos para Publicación

Para habilitar la publicación automática, configura estos secrets en GitHub:

- `OSSRH_USERNAME`: Usuario de Sonatype OSSRH
- `OSSRH_TOKEN`: Token de Sonatype OSSRH
- `GPG_PRIVATE_KEY`: Clave privada GPG (armored)
- `GPG_PASSPHRASE`: Passphrase de la clave GPG

## 📈 Métricas de Calidad

| Métrica | Valor | Umbral |
|---------|-------|--------|
| Tests Passing | 27/27 (100%) | ✅ |
| Coverage Líneas | >40% | ✅ |
| Coverage Complejidad | >30% | ✅ |
| Compilation | SUCCESS | ✅ |
| Java Version | 17+ | ✅ |

## 🤝 Contribuir

Las contribuciones son bienvenidas. Por favor:

1. Fork el repositorio
2. Crea una rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -am 'Añadir nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la licencia MIT - ver el archivo [LICENSE](LICENSE) para detalles.

## 👨‍💻 Autor

**Yasmin Ramos** - [yasmramos](https://github.com/yasmramos)

## 🔗 Enlaces Útiles

- [Repositorio GitHub](https://github.com/yasmramos/Licify)
- [Maven Central](https://central.sonatype.com/search?q=com.licify)
- [Documentación Javadoc](https://yasmramos.github.io/Licify/apidocs/)
- [Issue Tracker](https://github.com/yasmramos/Licify/issues)

---

<div align="center">

**Desarrollado con ☕ Java y ❤️**

[⬆️ Volver arriba](#licify---java-license-management-library-20)

</div>
