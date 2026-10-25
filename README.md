# Licify

A license management library for the JVM.

[![Java CI with Maven](https://github.com/yasmramos/Licify/actions/workflows/maven.yml/badge.svg)](https://github.com/yasmramos/Licify/actions/workflows/maven.yml)
[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](https://github.com/yasmramos/Licify/releases)
[![Maven Central](https://img.shields.io/badge/Maven%20Central-0.1.0-blue.svg)](https://central.sonatype.com/artifact/com.licify/licify)
[![Java Version](https://img.shields.io/badge/Java-17%2B-green.svg)](https://adoptium.net/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Advanced Configuration](#advanced-configuration)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Build and Test](#build-and-test)
- [CI/CD Pipeline](#cicd-pipeline)
- [Contributing](#contributing)
- [License](#license)

## Overview

Licify provides software vendors with a complete toolkit for issuing, signing,
serializing, validating, and revoking software licenses in Java applications.

Licenses are cryptographically signed with an RSA key pair owned by the vendor.
The end user's application verifies the signature with the embedded public key,
so a tampered license file can be detected reliably. Optional hardware binding
ties a license to a specific machine while tolerating minor hardware changes.

> **Status:** Early development (`0.x.y`). The API may change between minor
> releases. See [Roadmap](#roadmap).

## Features

| Area | Capabilities |
| --- | --- |
| **Licensing model** | Perpetual, trial, commercial, floating and custom license types; licensee/product metadata; feature flags; max-user limits; expiration dates |
| **Digital signatures** | `SHA256withRSA` / `SHA384withRSA` / `SHA512withRSA`; public-key fingerprint to prevent key substitution attacks |
| **Hybrid encryption** | AES session key + RSA key wrapping (RSA-2048/3072/4096, AES-128/256, OAEP padding) for encrypted license files |
| **Hardware binding** | Multi-component machine fingerprint (CPU, motherboard, disk, MAC) with configurable tolerance for minor hardware changes |
| **Serialization** | `BINARY`, `BASE64`, `STRING` and `JSON` license file formats |
| **Revocation** | Persistent revocation list keyed by unique license key; real-time checks |
| **Floating licenses** | Concurrent-session manager with heartbeats, idle eviction and session persistence across restarts |
| **Offline activation** | Activation-request / activation-response flow for air-gapped environments |
| **Short keys** | Deterministic seed-based short license keys (`SeedGenerator`, `ShortLicenseKey`) |
| **Tamper detection** | Integrity helpers that detect modified or replayed license files |
| **Analytics** | Usage aggregation over issued/validated licenses |

## Requirements

- **Java 17+** (LTS; also tested on Java 21)
- **Maven 3.8+** (only when building from source)

Runtime dependencies: Jackson (`jackson-databind`, `jackson-datatype-jsr310`)
for JSON handling and an SLF4J-compatible logging binding; both are pulled in
automatically by Maven/Gradle.

## Installation

### Maven

```xml
<dependency>
    <groupId>com.licify</groupId>
    <artifactId>licify</artifactId>
    <version>0.1.0</version>
</dependency>
```

### Gradle (Groovy DSL)

```groovy
implementation 'com.licify:licify:0.1.0'
```

### Gradle (Kotlin DSL)

```kotlin
implementation("com.licify:licify:0.1.0")
```

### Build from source

```bash
git clone https://github.com/yasmramos/Licify.git
cd Licify
mvn clean install
```

## Quick Start

### 1. Generate the vendor key pair (once)

```java
import com.licify.Licify;
import java.security.KeyPair;

KeyPair keyPair = Licify.generateKeyPair(); // RSA-2048 by default
// Persist these securely. The private key stays with the vendor;
// ship only the public key inside your product.
```

### 2. Issue and sign a license (vendor side)

```java
import com.licify.Licify;
import com.licify.Licify.License;
import java.time.LocalDateTime;

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
        .build();

Licify.sign(license, keyPair);          // SHA256withRSA + key fingerprint
Licify.save(license, "license.bin");    // format inferred from extension
```

### 3. Validate the license (customer side)

```java
import com.licify.Licify;
import com.licify.Licify.License;
import java.security.PublicKey;

License loaded = Licify.load("license.bin");

if (!Licify.isRevoke(loaded)                 // not revoked
        && Licify.verify(loaded, publicKey)  // signature intact
        && !loaded.isExpired()               // still valid
        && Licify.isValidLicense(loaded)) {  // business fields present
    System.out.println("Licensed to " + loaded.getLicenseeName());
}
```

### 4. Hardware-bound licenses

```java
// Issuing: bind to the current machine (or pass an explicit fingerprint)
License bound = new Licify.LicenseBuilder()
        .licenseeName("Jane Roe")
        .productId("MYPRODUCT-001")
        .hardwareId()                    // fingerprint of this machine
        .build();
Licify.sign(bound, keyPair);

// Validating: exact match first, then tolerant match
boolean ok = Licify.verifyLicenseForHardware(bound)
        || Licify.verifyLicenseForHardwareWithTolerance(bound);
```

## Core Concepts

### License lifecycle

```
 create ──► sign ──► distribute ──► load ──► verify ──► use
                                     │
                                 revoke ◄── (vendor adds license key to revocation list)
```

1. **Create** — build the license with `LicenseBuilder`.
2. **Sign** — `Licify.sign(...)` serializes the license payload and signs it
   with the vendor's private key; the public-key fingerprint is stored so a
   substituted key can be detected.
3. **Distribute** — save as `BINARY`, `BASE64`, `STRING` or `JSON`. Files can
   additionally be encrypted with `saveEncryptedLicense(...)`.
4. **Verify** — always check revocation **and** signature before trusting any
   field of the license. Hardware binding is checked after signature
   verification.
5. **Revoke** — `Licify.revoke(license)` adds the license key to the
   persistent revocation list.

### Verification order (security-critical)

`Licify.verify(...)` verifies the cryptographic signature **before** any
business or hardware check. Never validate mutable fields (expiration,
licensee, hardware id) of an unverified license: they come from an untrusted
file.

### License keys

Every license carries a unique `licenseKey`. Revocation and floating sessions
reference this key, so it must never be null on signed licenses.

## Advanced Configuration

### Encryption

```java
import com.licify.encryption.EncryptionConfig;

EncryptionConfig config = new EncryptionConfig.Builder()
        .setKeySize(4096)          // RSA key size
        .setAesKeySize(256)        // AES session key size
        .setTransformation("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        .build();

Licify.setDefaultEncryptionConfig(config);
```

### Signatures

```java
import com.licify.signing.SignatureConfig;

SignatureConfig sigConfig = new SignatureConfig.Builder()
        .algorithm("SHA512withRSA")
        .hashAlgorithm("SHA-512")
        .build();

Licify.setDefaultSignatureConfig(sigConfig);
```

### Encrypted license files

```java
Licify.saveEncryptedLicense(license, "license.sec", vendorPublicKey);
License decrypted = Licify.loadEncryptedLicense("license.sec", vendorPrivateKey);
```

### Floating licenses

```java
import com.licify.core.FloatingLicenseManager;

FloatingLicenseManager manager = new FloatingLicenseManager();
FloatingLicenseManager.ActivationResult result =
        manager.activateSession(license.getLicenseKey(), "client-42", "10.0.0.42", 50);
                                        // license key   client id   host      max users

if (result.isSuccess()) {
    manager.updateHeartbeat(result.getSessionId());   // keep-alive
    manager.deactivateSession(result.getSessionId()); // release seat
}
```

### Offline activation

```java
import com.licify.offline.OfflineActivationService;

OfflineActivationService svc = new OfflineActivationService(adminKeyPair);
String request = svc.generateActivationRequest(license, hardwareFingerprint);
// Customer sends `request` to the vendor; vendor returns an activation response.
svc.processActivationResponse(responseContent);
```

## API Reference

Main entry points on `com.licify.Licify` (all static):

| Method | Purpose |
| --- | --- |
| `generateKeyPair()` / `generateKeyPair(SignatureConfig)` | Create vendor RSA key pair |
| `sign(License, KeyPair)` | Sign a license and embed the key fingerprint |
| `verify(License, PublicKey)` | Verify signature (and, where applicable, key fingerprint) |
| `save(License, String[, IOFormat])` / `load(String[, IOFormat])` | Plain license files |
| `saveEncryptedLicense(...)` / `loadEncryptedLicense(...)` | Hybrid-encrypted license files |
| `revoke(License)` / `isRevoke(License)` / `getRevokedLicenses()` | Revocation list management |
| `isValidLicense(License)` / `isExpired(License)` | Business-level validity checks |
| `verifyLicenseForHardware(License)` | Exact hardware match |
| `verifyLicenseForHardwareWithTolerance(License)` | Tolerant hardware match |
| `refreshHardwareId()` | Invalidate the cached hardware fingerprint |

Full Javadoc: <https://yasmramos.github.io/Licify/apidocs/>

## Project Structure

```
src/main/java/com/licify/
├── Licify.java                  # Public API facade
├── LicenseKeyPair.java          # Key generation helpers
├── SeedGenerator.java           # Deterministic seeds for short keys
├── core/                        # Serializer, revocation, floating licenses, auto-update
├── encryption/                  # Hybrid (AES + RSA) encryption
├── signing/                     # Digital signatures and configuration
├── hardware/                    # Hardware fingerprinting and backup
├── io/                          # License file formats
├── offline/                     # Air-gapped activation flow
├── security/                    # Tamper detection
├── analytics/                   # Usage analytics
├── util/                        # Key and date/time helpers
└── exception/                   # ValidationException
```

## Build and Test

```bash
mvn clean verify          # compile, test, Checkstyle, JaCoCo report
mvn test                  # unit tests only
mvn jacoco:report         # coverage report -> target/site/jacoco/
mvn javadoc:javadoc       # API docs -> target/site/apidocs/
```

The suite contains 80 tests covering signing, verification, serialization,
encryption, hardware binding, revocation, floating licenses, offline
activation and tamper detection.

## CI/CD Pipeline

GitHub Actions (`.github/workflows/maven.yml`) builds and tests the project on
**Java 17 and 21** for every push and pull request, runs static analysis and
publishes artifacts on tagged releases.

Required repository secrets for publishing to Maven Central:

| Secret | Description |
| --- | --- |
| `OSSRH_USERNAME` | Sonatype central portal username |
| `OSSRH_TOKEN` | Sonatype central portal token |
| `GPG_PRIVATE_KEY` | GPG private key (armored) |
| `GPG_PASSPHRASE` | GPG key passphrase |

## Roadmap

- [ ] Stabilize the public API for `1.0.0`
- [ ] Move `hardwareId` out of the signed payload (allows hardware re-binding
      without re-signing)
- [ ] Remote revocation lists (HTTP feed)
- [ ] Sample projects and framework integrations (Spring, Quarkus)

## Contributing

Contributions are welcome. This project uses
[Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`); all code, comments
and documentation are written in English.

1. Fork the repository and branch off `develop`
   (`git checkout -b feat/my-feature`).
2. Keep commits conventional and signed-off work focused; add tests.
3. Ensure `mvn clean verify` passes.
4. Open a Pull Request against `develop`.

## License

Distributed under the [MIT License](LICENSE).

## Author

**Yasmany Ramos** — [@yasmramos](https://github.com/yasmramos)
