package com.licify.offline;

import com.licify.Licify.License;
import com.licify.signing.DigitalSignature;
import com.licify.LicenseKeyPair;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * Manages offline license activation requests and responses.
 * Useful for air-gapped systems or environments without direct internet access.
 */
public class OfflineActivationService {

    private final LicenseKeyPair keyPair;
    private final PublicKey adminPublicKey;

    /**
     * Constructor por defecto que genera un nuevo par de claves.
     * Nota: En producción, las claves deberían ser persistentes y compartidas entre cliente/servidor.
     */
    public OfflineActivationService() throws Exception {
        this.keyPair = LicenseKeyPair.generate();
        this.adminPublicKey = null;
    }

    /**
     * Constructor con par de claves específico para testing.
     */
    public OfflineActivationService(LicenseKeyPair keyPair) {
        this.keyPair = keyPair;
        this.adminPublicKey = keyPair.getPublicKey();
    }

    /**
     * Generates an activation request file content based on the license and machine fingerprint.
     * This file should be sent to the license administrator to generate a response.
     *
     * @param license The license to activate.
     * @param fingerprint The machine fingerprint.
     * @return Base64 encoded activation request string.
     * @throws Exception If signature generation fails.
     */
    public String generateActivationRequest(License license, String fingerprint) throws Exception {
        if (license == null || fingerprint == null) {
            throw new IllegalArgumentException("License and fingerprint cannot be null");
        }

        String rawData = license.getLicenseKey() + "|" + fingerprint + "|" + System.currentTimeMillis();
        String signature = DigitalSignature.signSHA512(rawData, keyPair.getPrivateKey());
        
        return Base64.getEncoder().encodeToString((rawData + "::" + signature).getBytes());
    }

    /**
     * Saves the activation request to a file.
     *
     * @param requestContent The Base64 encoded request content.
     * @param filePath The path to save the request file.
     * @throws Exception If file writing fails.
     */
    public void saveActivationRequest(String requestContent, String filePath) throws Exception {
        Path path = Paths.get(filePath);
        Files.writeString(path, requestContent);
    }

    /**
     * Processes an activation response from the administrator.
     * Validates the signature and returns an activated license token.
     *
     * @param responseContent The Base64 encoded response content.
     * @return A validation token or success message.
     * @throws Exception If validation fails or signature is invalid.
     */
    public String processActivationResponse(String responseContent) throws Exception {
        byte[] decodedBytes = Base64.getDecoder().decode(responseContent);
        String decodedString = new String(decodedBytes);
        
        String[] parts = decodedString.split("::");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid response format");
        }

        String data = parts[0];
        String signature = parts[1];

        // Verify signature using the stored public key
        boolean isValid = DigitalSignature.verifySHA512(data, signature, keyPair.getPublicKey());
        
        if (!isValid) {
            throw new SecurityException("Invalid activation response signature");
        }

        // In a real scenario, parse data to extract specific activation tokens or updated license info
        return "Activation Successful. Token: " + Base64.getEncoder().encodeToString(("ACTIVATED_" + System.currentTimeMillis()).getBytes());
    }

    /**
     * Loads an activation request from a file.
     *
     * @param filePath The path to the request file.
     * @return The content of the request file.
     * @throws Exception If file reading fails.
     */
    public String loadActivationRequest(String filePath) throws Exception {
        Path path = Paths.get(filePath);
        return Files.readString(path);
    }
    
    /**
     * Obtiene el par de claves para uso en tests.
     */
    public LicenseKeyPair getKeyPair() {
        return keyPair;
    }
}
