package com.licify.encryption;

public class EncryptionConfig {

    private String rsaAlgorithm = "RSA";
    private String rsaTransformation = "RSA/ECB/PKCS1Padding";
    private String aesAlgorithm = "AES";
    private String aesTransformation = "AES/GCM/NoPadding";
    private int aesKeySize = 256; // 128, 192, or 256
    private int gcmTagLength = 128; // 128, 120, 112, 104, or 96
    private int gcmIvLength = 12; // 12 bytes recommended for GCM

    public EncryptionConfig() {
    }

    public String getRsaAlgorithm() {
        return rsaAlgorithm;
    }

    public void setRsaAlgorithm(String rsaAlgorithm) {
        this.rsaAlgorithm = rsaAlgorithm;
    }

    public String getRsaTransformation() {
        return rsaTransformation;
    }

    public void setRsaTransformation(String rsaTransformation) {
        this.rsaTransformation = rsaTransformation;
    }

    public String getAesAlgorithm() {
        return aesAlgorithm;
    }

    public void setAesAlgorithm(String aesAlgorithm) {
        this.aesAlgorithm = aesAlgorithm;
    }

    public String getAesTransformation() {
        return aesTransformation;
    }

    public void setAesTransformation(String aesTransformation) {
        this.aesTransformation = aesTransformation;
    }

    public int getAesKeySize() {
        return aesKeySize;
    }

    public void setAesKeySize(int aesKeySize) {
        this.aesKeySize = aesKeySize;
    }

    public int getGcmTagLength() {
        return gcmTagLength;
    }

    public void setGcmTagLength(int gcmTagLength) {
        this.gcmTagLength = gcmTagLength;
    }

    public int getGcmIvLength() {
        return gcmIvLength;
    }

    public void setGcmIvLength(int gcmIvLength) {
        this.gcmIvLength = gcmIvLength;
    }

    /**
     * Creates a defensive copy of this configuration so shared defaults cannot be
     * mutated through external references.
     *
     * @return a new EncryptionConfig with the same values as this one
     */
    public EncryptionConfig copy() {
        EncryptionConfig copy = new EncryptionConfig();
        copy.rsaAlgorithm = this.rsaAlgorithm;
        copy.rsaTransformation = this.rsaTransformation;
        copy.aesAlgorithm = this.aesAlgorithm;
        copy.aesTransformation = this.aesTransformation;
        copy.aesKeySize = this.aesKeySize;
        copy.gcmTagLength = this.gcmTagLength;
        copy.gcmIvLength = this.gcmIvLength;
        return copy;
    }

    public static class Builder {

        private final EncryptionConfig config = new EncryptionConfig();

        public Builder rsaAlgorithm(String algorithm) {
            config.setRsaAlgorithm(algorithm);
            return this;
        }

        public Builder rsaTransformation(String transformation) {
            config.setRsaTransformation(transformation);
            return this;
        }

        public Builder aesAlgorithm(String algorithm) {
            config.setAesAlgorithm(algorithm);
            return this;
        }

        public Builder aesTransformation(String transformation) {
            config.setAesTransformation(transformation);
            return this;
        }

        public Builder aesKeySize(int keySize) {
            config.setAesKeySize(keySize);
            return this;
        }

        public Builder gcmTagLength(int tagLength) {
            config.setGcmTagLength(tagLength);
            return this;
        }

        public Builder gcmIvLength(int ivLength) {
            config.setGcmIvLength(ivLength);
            return this;
        }

        public EncryptionConfig build() {
            return config;
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
