package com.licify.signing;

import java.util.Objects;

/**
 * Configuración de firma
 */
public class SignatureConfig {

    private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String DEFAULT_HASH_ALGORITHM = "SHA-256";
    private static final int DEFAULT_KEY_SIZE = 2048;
    private static final int MIN_KEY_SIZE = 1024;
    private static final int MAX_KEY_SIZE = 4096;

    private String algorithm = DEFAULT_SIGNATURE_ALGORITHM;
    private int keySize = DEFAULT_KEY_SIZE;
    private String hashAlgorithm = DEFAULT_HASH_ALGORITHM;
    private String provider = "SunRsaSign"; // Default security provider
    private boolean enablePSS = false; // For RSA-PSS padding
    private String keyId; // Optional key identifier

    public SignatureConfig() {
    }

    public SignatureConfig(String algorithm, int keySize) {
        setAlgorithm(algorithm);
        setKeySize(keySize);
    }

    public SignatureConfig(String algorithm, int keySize, String hashAlgorithm) {
        this(algorithm, keySize);
        setHashAlgorithm(hashAlgorithm);
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.trim().isEmpty()) {
            throw new IllegalArgumentException("Algorithm cannot be null or empty");
        }
        this.algorithm = algorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        if (keySize < MIN_KEY_SIZE || keySize > MAX_KEY_SIZE) {
            throw new IllegalArgumentException(
                    String.format("Key size must be between %d and %d", MIN_KEY_SIZE, MAX_KEY_SIZE)
            );
        }
        // Ensure key size is appropriate for the algorithm
        if (algorithm.contains("RSA") && keySize % 64 != 0) {
            throw new IllegalArgumentException("RSA key size must be a multiple of 64");
        }
        if (algorithm.contains("EC") && (keySize != 256 && keySize != 384 && keySize != 521)) {
            throw new IllegalArgumentException("EC key size must be 256, 384, or 521");
        }
        this.keySize = keySize;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        if (hashAlgorithm == null || hashAlgorithm.trim().isEmpty()) {
            throw new IllegalArgumentException("Hash algorithm cannot be null or empty");
        }
        this.hashAlgorithm = hashAlgorithm;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public boolean isEnablePSS() {
        return enablePSS;
    }

    public void setEnablePSS(boolean enablePSS) {
        this.enablePSS = enablePSS;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    /**
     * Validates the configuration for consistency
     */
    public void validate() {
        // Validate algorithm and hash combination
        if (algorithm.startsWith("SHA") && !hashAlgorithm.startsWith("SHA")) {
            throw new IllegalStateException("Hash algorithm must match signature algorithm pattern");
        }

        // Additional validation logic can be added here
    }

    /**
     * Creates a copy of this configuration
     */
    public SignatureConfig copy() {
        SignatureConfig copy = new SignatureConfig();
        copy.algorithm = this.algorithm;
        copy.keySize = this.keySize;
        copy.hashAlgorithm = this.hashAlgorithm;
        copy.provider = this.provider;
        copy.enablePSS = this.enablePSS;
        copy.keyId = this.keyId;
        return copy;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        SignatureConfig that = (SignatureConfig) o;
        return keySize == that.keySize
                && enablePSS == that.enablePSS
                && Objects.equals(algorithm, that.algorithm)
                && Objects.equals(hashAlgorithm, that.hashAlgorithm)
                && Objects.equals(provider, that.provider)
                && Objects.equals(keyId, that.keyId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, keySize, hashAlgorithm, provider, enablePSS, keyId);
    }

    @Override
    public String toString() {
        return "SignatureConfig{"
                + "algorithm='" + algorithm + '\''
                + ", keySize=" + keySize
                + ", hashAlgorithm='" + hashAlgorithm + '\''
                + ", provider='" + provider + '\''
                + ", enablePSS=" + enablePSS
                + ", keyId='" + keyId + '\''
                + '}';
    }

    /**
     * Builder pattern for fluent configuration
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private final SignatureConfig config = new SignatureConfig();

        public Builder algorithm(String algorithm) {
            config.setAlgorithm(algorithm);
            return this;
        }

        public Builder keySize(int keySize) {
            config.setKeySize(keySize);
            return this;
        }

        public Builder hashAlgorithm(String hashAlgorithm) {
            config.setHashAlgorithm(hashAlgorithm);
            return this;
        }

        public Builder provider(String provider) {
            config.setProvider(provider);
            return this;
        }

        public Builder enablePSS(boolean enablePSS) {
            config.setEnablePSS(enablePSS);
            return this;
        }

        public Builder keyId(String keyId) {
            config.setKeyId(keyId);
            return this;
        }

        public SignatureConfig build() {
            config.validate();
            return config;
        }
    }
}
