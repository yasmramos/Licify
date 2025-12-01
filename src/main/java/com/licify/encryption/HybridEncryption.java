package com.licify.encryption;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HybridEncryption {

    private final EncryptionConfig defaultEncryptionConfig;

    public HybridEncryption(EncryptionConfig defaultEncryptionConfig) {
        this.defaultEncryptionConfig = defaultEncryptionConfig;
    }

    /**
     * Cifrado híbrido: RSA + AES Retorna un objeto con la clave AES cifrada y
     * los datos cifrados
     */
    public HybridEncryptionResult hybridEncrypt(byte[] data, PublicKey publicKey) throws Exception {
        return hybridEncrypt(data, publicKey, defaultEncryptionConfig);
    }

    public HybridEncryptionResult hybridEncrypt(byte[] data, PublicKey publicKey, EncryptionConfig config) throws Exception {
        // Generar clave AES
        SecretKey aesKey = generateAesKey(config.getAesKeySize());

        // Cifrar datos con AES
        byte[] encryptedData = encryptWithAes(data, aesKey, config);

        // Cifrar clave AES con RSA
        byte[] encryptedAesKey = encryptAesKeyWithRsa(aesKey, publicKey, config);

        return new HybridEncryptionResult(encryptedAesKey, encryptedData);
    }

    /**
     * Descifrado híbrido: RSA + AES
     */
    public byte[] hybridDecrypt(HybridEncryptionResult encryptedData, PrivateKey privateKey) throws Exception {
        return hybridDecrypt(encryptedData, privateKey, defaultEncryptionConfig);
    }

    public byte[] hybridDecrypt(HybridEncryptionResult encryptedData, PrivateKey privateKey, EncryptionConfig config) throws Exception {
        // Descifrar clave AES con RSA
        SecretKey aesKey = decryptAesKeyWithRsa(encryptedData.getEncryptedAesKey(), privateKey, config);

        // Descifrar datos con AES
        return decryptWithAes(encryptedData.getEncryptedData(), aesKey, config);
    }

    /**
     * Descifra datos con AES-GCM
     */
    public byte[] decryptWithAes(byte[] encryptedData, SecretKey aesKey) throws Exception {
        return decryptWithAes(encryptedData, aesKey, defaultEncryptionConfig);
    }

    public static byte[] decryptWithAes(byte[] encryptedData, SecretKey aesKey, EncryptionConfig config) throws Exception {
        // Separar IV y datos cifrados
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, config.getGcmIvLength());
        byte[] actualEncryptedData = Arrays.copyOfRange(encryptedData, config.getGcmIvLength(), encryptedData.length);

        // Configurar cipher GCM
        Cipher cipher = Cipher.getInstance(config.getAesTransformation());
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(config.getGcmTagLength(), iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParameterSpec);

        return cipher.doFinal(actualEncryptedData);
    }

    /**
     * Cifra una clave AES con RSA (usando clave pública)
     */
    public byte[] encryptAesKeyWithRsa(SecretKey aesKey, PublicKey publicKey) throws Exception {
        return encryptAesKeyWithRsa(aesKey, publicKey, defaultEncryptionConfig);
    }

    public static byte[] encryptAesKeyWithRsa(SecretKey aesKey, PublicKey publicKey, EncryptionConfig config) throws Exception {
        Cipher cipher = Cipher.getInstance(config.getRsaTransformation());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }

    /**
     * Descifra una clave AES con RSA (usando clave privada)
     */
    public SecretKey decryptAesKeyWithRsa(byte[] encryptedAesKey, PrivateKey privateKey) throws Exception {
        return decryptAesKeyWithRsa(encryptedAesKey, privateKey, defaultEncryptionConfig);
    }

    public static SecretKey decryptAesKeyWithRsa(byte[] encryptedAesKey, PrivateKey privateKey, EncryptionConfig config) throws Exception {
        Cipher cipher = Cipher.getInstance(config.getRsaTransformation());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKey = cipher.doFinal(encryptedAesKey);
        return new SecretKeySpec(decryptedKey, 0, decryptedKey.length, config.getAesAlgorithm());
    }

    /**
     * Cifra datos con AES-GCM
     */
    public byte[] encryptWithAes(byte[] data, SecretKey aesKey) throws Exception {
        return encryptWithAes(data, aesKey, defaultEncryptionConfig);
    }

    public byte[] encryptWithAes(byte[] data, SecretKey aesKey, EncryptionConfig config) throws Exception {
        // Generar IV aleatorio
        byte[] iv = new byte[config.getGcmIvLength()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Configurar cipher GCM
        Cipher cipher = Cipher.getInstance(config.getAesTransformation());
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(config.getGcmTagLength(), iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParameterSpec);

        // Cifrar datos
        byte[] encryptedData = cipher.doFinal(data);

        // Combinar IV + datos cifrados
        byte[] result = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedData, 0, result, iv.length, encryptedData.length);

        return result;
    }

    /**
     * Genera una clave AES segura
     */
    public SecretKey generateAesKey() throws NoSuchAlgorithmException {
        return generateAesKey(defaultEncryptionConfig.getAesKeySize());
    }

    public SecretKey generateAesKey(int keySize) throws NoSuchAlgorithmException {
        javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance(defaultEncryptionConfig.getAesAlgorithm());
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

}
