# Licify - Java License Management Library 2.0

[![Java CI with Maven](https://github.com/yasmramos/Licify/actions/workflows/maven.yml/badge.svg)](https://github.com/yasmramos/Licify/actions/workflows/maven.yml)
[![Maven Central](https://img.shields.io/badge/Maven%20Central-2.0.0-blue.svg)](https://central.sonatype.com/artifact/com.licify/licify)
[![Java Version](https://img.shields.io/badge/Java-17%2B-green.svg)](https://adoptium.net/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📖 Overview

**Licify** is a robust and modern Java library for software license management, providing advanced features including hybrid encryption (AES+RSA), digital signatures, hardware validation, and multiple serialization formats.

### ✨ What's New in Version 2.0

- ✅ **Java 17+:** Updated to the latest language features
- ✅ **Complete CI/CD:** GitHub Actions with multi-version builds (Java 17 and 21)
- ✅ **Automatic Publishing:** Configured for Maven Central
- ✅ **Enhanced Documentation:** Complete Javadocs and detailed examples
- ✅ **New Features:** Floating licenses, automatic update system
- ✅ **Code Quality:** Checkstyle, JaCoCo coverage >40%

## 🚀 Key Features

### 🔒 Hybrid Encryption
- Combination of symmetric (AES-256) and asymmetric (RSA-2048/3072/4096) algorithms
- Flexible security parameter configuration
- Support for multiple key sizes
- Secure session key management

### ✍️ Digital Signatures
- Cryptographic integrity validation
- Configurable algorithms (SHA256withRSA, SHA384withRSA, SHA512withRSA)
- Automatic authenticity verification
- Public key fingerprint

### 🖥️ Hardware Identification
- License binding to specific hardware
- Multi-component analysis (CPU, motherboard, disk, MAC)
- Hardware configuration backup
- Tolerance to minor hardware changes

### 📝 Multiple Formats
- **BINARY:** Maximum efficiency and compactness
- **STRING:** Human readability (Base64)
- **XML:** Interoperability with external systems
- **PROPERTIES:** Integration with configuration files

### 🔄 Revocation System
- Blacklist of revoked licenses
- JSON file persistence
- Real-time verification
- Scheduled cleanup

### 🎯 Seed Generation
- Deterministic cryptographic seeds
- Multiple hash algorithms (SHA-256/384/512)
- System entropy included
- Ideal for offline licenses

## 📦 Installation

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

### Prerequisites
- **Java:** 17 or higher
- **Maven:** 3.8+ (for building)

## ⚡ Quick Start

### 1. Generate Key Pair

```java
import com.licify.LicenseKeyPair;
import java.security.KeyPair;

// Generate RSA key pair
KeyPair keyPair = LicenseKeyPair.generateKeyPair(2048);

// Save keys
LicenseKeyPair.saveKeyPair(keyPair, "keys/");
```

### 2. Create a License

```java
import com.licify.Licify;
import com.licify.Licify.License;
import java.time.LocalDateTime;

Licify licify = new Licify();

License license = new Licify.LicenseBuilder()
    .licenseeName("John Doe")
    .licenseeEmail("john@example.com")
    .productId("MYPRODUCT-001")
    .productVersion("1.0.0")
    .expirationDate(LocalDateTime.now().plusYears(1))
    .maxUsers(10)
    .feature("premium-support")
    .feature("cloud-sync")
    .licenseType("COMMERCIAL")
    .hardwareId()  // Uses current hardware
    .build();
```

### 3. Sign the License

```java
import java.security.KeyPair;

// Load private key
KeyPair keyPair = LicenseKeyPair.loadKeyPair("keys/");

// Sign license
licify.sign(license, keyPair);

System.out.println("Signed license: " + license.getSignature());
```

### 4. Save License

```java
import com.licify.io.IOFormat;

// Save in binary format
licify.save(license, "license.bin", IOFormat.BINARY);

// Or save in XML format
licify.save(license, "license.xml", IOFormat.XML);
```

### 5. Load and Validate License

```java
import com.licify.Licify.ValidationResult;

// Load license
License loadedLicense = licify.load("license.bin", IOFormat.BINARY);

// Validate signature
ValidationResult result = licify.validateSignature(loadedLicense, keyPair.getPublic());
if (result.isValid()) {
    System.out.println("✅ Valid license");
} else {
    System.err.println("❌ Invalid license: " + result.getErrors());
}

// Check expiration
if (loadedLicense.isExpired()) {
    System.err.println("⚠️ Expired license");
}

// Verify hardware
boolean hardwareMatch = licify.validateHardwareId(loadedLicense);
if (!hardwareMatch) {
    System.err.println("⚠️ Hardware mismatch");
}
```

## 🔧 Advanced Configuration

### Configure Custom Encryption

```java
import com.licify.encryption.EncryptionConfig;

EncryptionConfig config = new EncryptionConfig.Builder()
    .setKeySize(4096)           // RSA 4096 bits
    .setAesKeySize(256)         // AES 256 bits
    .setTransformation("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    .build();

licify.setDefaultEncryptionConfig(config);
```

### Configure Digital Signature

```java
import com.licify.signing.SignatureConfig;

SignatureConfig sigConfig = new SignatureConfig.Builder()
    .algorithm("SHA512withRSA")
    .provider("SunRsaSign")
    .hashAlgorithm("SHA-512")
    .build();

licify.setDefaultSignatureConfig(sigConfig);
```

### Floating Licenses (Network)

```java
// Create floating license for network
License floatingLicense = new Licify.LicenseBuilder()
    .licenseeName("Company Inc.")
    .productId("NETWORK-LICENSE")
    .maxUsers(50)  // 50 concurrent users
    .licenseType("FLOATING")
    .customData("{\"server\":\"license-server.example.com\",\"port\":27000}")
    .build();
```

## 🧪 Running Tests

```bash
# Compile project
mvn clean compile

# Run tests
mvn test

# Generate coverage report
mvn jacoco:report

# Verify code quality
mvn verify

# Full build
mvn clean install
```

Reports are generated in:
- `target/surefire-reports/` - Test results
- `target/site/jacoco/` - HTML code coverage
- `target/jacoco.exec` - Execution data

## 📊 Project Structure

```
Licify/
├── src/main/java/com/licify/
│   ├── Licify.java              # Main API
│   ├── LicenseKeyPair.java      # Key management
│   ├── SeedGenerator.java       # Seed generation
│   ├── Main.java                # Entry point
│   ├── core/                    # Core functionality
│   │   ├── LicenseSerializer.java
│   │   ├── LicenseRevocationManager.java
│   │   └── ShortLicenseKey.java
│   ├── encryption/              # Hybrid encryption
│   │   ├── HybridEncryption.java
│   │   ├── EncryptionConfig.java
│   │   └── HybridEncryptionResult.java
│   ├── signing/                 # Digital signatures
│   │   ├── DigitalSignature.java
│   │   └── SignatureConfig.java
│   ├── hardware/                # Hardware identification
│   │   ├── HardwareId.java
│   │   └── HardwareIdBackup.java
│   ├── io/                      # I/O formats
│   │   └── IOFormat.java
│   ├── util/                    # Utilities
│   │   ├── KeyUtils.java
│   │   └── DateTimeUtils.java
│   └── exception/               # Exceptions
│       └── ValidationException.java
├── src/test/java/com/licify/
│   └── LicifyTest.java          # Test suite
├── .github/workflows/
│   └── maven.yml                # CI/CD pipeline
├── pom.xml                      # Maven configuration
└── README.md                    # This documentation
```

## 🏗️ CI/CD Pipeline

The project includes a complete GitHub Actions pipeline that:

1. **Multi-Version Build:** Compiles with Java 17 and 21
2. **Automated Tests:** Runs 27 unit tests
3. **Coverage:** Generates JaCoCo reports
4. **Quality:** Executes Checkstyle and Javadoc validation
5. **Publishing:** Deploys to Maven Central on releases

### Required Secrets for Publishing

To enable automatic publishing, configure these secrets in GitHub:

- `OSSRH_USERNAME`: Sonatype OSSRH username
- `OSSRH_TOKEN`: Sonatype OSSRH token
- `GPG_PRIVATE_KEY`: GPG private key (armored)
- `GPG_PASSPHRASE`: GPG key passphrase

## 📈 Quality Metrics

| Metric | Value | Threshold |
|---------|-------|--------|
| Tests Passing | 27/27 (100%) | ✅ |
| Line Coverage | >40% | ✅ |
| Complexity Coverage | >30% | ✅ |
| Compilation | SUCCESS | ✅ |
| Java Version | 17+ | ✅ |

## 🤝 Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

## 📄 License

This project is under the MIT license - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Yasmin Ramos** - [yasmramos](https://github.com/yasmramos)

## 🔗 Useful Links

- [GitHub Repository](https://github.com/yasmramos/Licify)
- [Maven Central](https://central.sonatype.com/search?q=com.licify)
- [Javadoc Documentation](https://yasmramos.github.io/Licify/apidocs/)
- [Issue Tracker](https://github.com/yasmramos/Licify/issues)

---

<div align="center">

**Built with ☕ Java and ❤️**

[⬆️ Back to top](#licify---java-license-management-library-20)

</div>
