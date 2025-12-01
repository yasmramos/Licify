package com.licify.encryption;

import java.io.Serializable;

/**
 * Clase para almacenar el resultado del cifrado híbrido
 */
public class HybridEncryptionResult implements Serializable {

    private static final long serialVersionUID = 1L;
    private byte[] encryptedAesKey;
    private byte[] encryptedData;

    public HybridEncryptionResult(byte[] encryptedAesKey, byte[] encryptedData) {
        this.encryptedAesKey = encryptedAesKey;
        this.encryptedData = encryptedData;
    }

    public byte[] getEncryptedAesKey() {
        return encryptedAesKey;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }
}
