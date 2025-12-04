# Licify - Java License Management Library

## Description
Licify is a robust Java library for software license management, providing advanced functionalities of hybrid encryption, digital signatures, hardware validation, and multiple serialization formats.

## Current Status
- ✅ **Tests**: 27/27 passing (100% success)
- ✅ **Compilation**: BUILD SUCCESS
- ✅ **Coverage**: JaCoCo reports generated
- ✅ **GitHub**: Repository synchronized

## Main Features

### 🔒 Hybrid Encryption
- Combination of symmetric (AES) and asymmetric (RSA) algorithms
- Flexible security parameter configuration
- Support for multiple key sizes

### ✍️ Digital Signatures
- Cryptographic integrity validation
- Customizable algorithm configuration
- Automatic authenticity verification

### 🖥️ Hardware Identification
- License binding to specific hardware
- Multiple hardware components analyzed
- Hardware configuration backup

### 📝 Multiple Formats
- BINARY: For maximum efficiency
- STRING: For human readability
- XML: For interoperability
- PROPERTIES: For configuration

### 🧬 Seed Generation
- Deterministic cryptographic seeds
- Multiple hash algorithms (SHA-256/384/512)
- System entropy included

## Project Structure

```
Licify/
├── src/
│   ├── main/java/com/licify/
│   │   ├── Licify.java              # Main API
│   │   ├── LicenseKeyPair.java      # Key management
│   │   ├── SeedGenerator.java       # Cryptographic seeds
│   │   ├── core/                    # Core functionalities
│   │   ├── encryption/              # Hybrid encryption
│   │   ├── signing/                 # Digital signatures
│   │   ├── hardware/                # HW identification
│   │   ├── io/                      # I/O formats
│   │   ├── util/                    # Utilities
│   │   └── exception/               # Exceptions
│   └── test/java/com/licify/
│       └── LicifyTest.java          # Test suite
├── target/                          # Compiled files
├── pom.xml                          # Maven configuration
└── module-info.java                 # Module definition
```

## Quick Start

### Prerequisites
- Java 17 or higher
- Maven 3.8 or higher

### Compilation
```bash
mvn clean compile
```

### Test Execution
```bash
mvn test
```

### Build and Tests
```bash
mvn clean install
```

## Usage Examples

### Create a License
```java
Licify licify = new Licify();

// Create basic license
License license = licify.createLicense()
    .withProductName("My Product")
    .withVersion("1.0.0")
    .withUserId("user123")
    .withExpiryDate(LocalDateTime.now().plusYears(1))
    .build();

// Save license
licify.saveLicense(license, "my_license.lic", IOFormat.BINARY);
```

### Validate a License
```java
License license = licify.loadLicense("my_license.lic", IOFormat.BINARY);
ValidationResult result = licify.validateLicense(license);
if (result.isValid()) {
    System.out.println("Valid license");
} else {
    System.out.println("Invalid license: " + result.getErrors());
}
```

### Encrypt Data
```java
HybridEncryptionResult result = licify.encryptData("sensitive data");
String encryptedData = result.getEncryptedData();
String decryptionKey = result.getDecryptionKey();
```

## Tests and Quality

### Test Coverage
- **Total**: 27 tests
- **Success**: 27 tests
- **Failures**: 0 tests
- **Time**: 6.559s

### Generated Reports
- `target/surefire-reports/` - Test reports
- `target/site/jacoco/` - HTML coverage analysis
- `target/jacoco.exec` - Execution data

## Maven Configuration

### Dependency
```xml
<dependency>
    <groupId>com.licify</groupId>
    <artifactId>licify</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Configured Plugins
- **Maven Compiler Plugin**: Java 17
- **Maven Surefire Plugin**: Test execution
- **JaCoCo Plugin**: Coverage analysis
- **Maven JAR Plugin**: Packaging

## Recent Fixes

### Test `testGenerateSeed`
- ✅ **Fixed**: Validation of cryptographic seeds instead of plain text
- **Impact**: Tests now validate appropriate cryptographic properties

### Test `testSaveAndLoadString`
- ✅ **Fixed**: NoSuchFileException elimination
- **Solution**: Changed from Files.write() to FileOutputStream + BufferedWriter
- **Impact**: STRING format now works correctly

## Available Assets

1. **`Licify-Fuente-Completo.zip`** - Complete source code with fixes
2. **`Licify-Codigo-Java.zip`** - Java code only and essential configuration
3. **`Licify-Dependencias-Compiladas.zip`** - Compiled files and reports
4. **`ASSETS-DOCUMENTACION.md`** - Complete assets documentation

## Repository
- **GitHub**: https://github.com/yasmramos/Licify
- **Status**: Synchronized with latest fixes

## License
Open source project for educational and development purposes.

---

**Developed by yasmramos** - Java project developer specializing in license management systems