package com.licify.core;

import com.licify.Licify.License;

/**
 * Utility class for serializing License objects with metadata into a standardized string format.
 * This class provides methods to convert License objects into a key-value pair format suitable
 * for storage, transmission, or digital signature verification.
 */
public class LicenseSerializer {

    /**
     * Serializes a License object with all its metadata into a standardized string format.
     * The output format uses key-value pairs separated by newlines, making it human-readable
     * and easily parsable. Null values are converted to empty strings to maintain format consistency.
     *
     * @param license the License object to serialize. Must not be null.
     * @return a string containing all license metadata in key=value format, with each field
     *         separated by a newline character. Returns an empty string if license is null.
     *
     * @apiNote The serialized format includes:
     * - Basic license information (version, licensee details, dates)
     * - Product information (ID, version, license key)
     * - Usage constraints (trial status, max users, features)
     * - License type and custom data
     * - Security information (signature, algorithm, public key fingerprint)
     * - Hardware binding information
     *
     * @example
     * version=1.0
     * licenseeName=John Doe
     * licenseeEmail=john@example.com
     * issueDate=2023-01-01
     * expirationDate=2024-01-01
     * productId=PROD-001
     * productVersion=2.1.0
     * licenseKey=ABC123-XYZ789
     * isTrial=false
     * maxUsers=5
     * features=FEAT1,FEAT2,FEAT3
     * licenseType=COMMERCIAL
     * customData=additional_info
     * signatureAlgorithm=RSA
     * signature=base64_signature_data
     * publicKeyFingerprint=sha256:abc123...
     * hardwareId=system_fingerprint
     */
    public static String serializeLicenseWithMetadata(License license) {
        // Handle null license to prevent NullPointerException
        if (license == null) {
            return "";
        }
        
        StringBuilder sb = new StringBuilder();
        
        // Basic license information
        sb.append("version=").append(license.getVersion() != null ? license.getVersion() : "").append("\n");
        sb.append("licenseeName=").append(license.getLicenseeName() != null ? license.getLicenseeName() : "").append("\n");
        sb.append("licenseeEmail=").append(license.getLicenseeEmail() != null ? license.getLicenseeEmail() : "").append("\n");
        sb.append("issueDate=").append(license.getIssueDate() != null ? license.getIssueDate().toString() : "").append("\n");
        sb.append("expirationDate=").append(license.getExpirationDate() != null ? license.getExpirationDate().toString() : "").append("\n");
        
        // Product information
        sb.append("productId=").append(license.getProductId() != null ? license.getProductId() : "").append("\n");
        sb.append("productVersion=").append(license.getProductVersion() != null ? license.getProductVersion() : "").append("\n");
        sb.append("licenseKey=").append(license.getLicenseKey() != null ? license.getLicenseKey() : "").append("\n");
        
        // Usage constraints and features
        sb.append("isTrial=").append(license.isTrial()).append("\n");
        sb.append("maxUsers=").append(license.getMaxUsers()).append("\n");
        sb.append("features=").append(license.getFeaturesAsString()).append("\n");
        
        // License type and custom data
        sb.append("licenseType=").append(license.getLicenseType() != null ? license.getLicenseType() : "").append("\n");
        sb.append("customData=").append(license.getCustomData() != null ? license.getCustomData() : "").append("\n");
        
        // Security information
        sb.append("signatureAlgorithm=").append(license.getSignatureAlgorithm() != null ? license.getSignatureAlgorithm() : "").append("\n");
        sb.append("signature=").append(license.getSignature() != null ? license.getSignature() : "").append("\n");
        sb.append("publicKeyFingerprint=").append(license.getPublicKeyFingerprint() != null ? license.getPublicKeyFingerprint() : "").append("\n");
        
        // Hardware binding
        sb.append("hardwareId=").append(license.getHardwareId() != null ? license.getHardwareId() : "").append("\n");
        
        return sb.toString();
    }
}