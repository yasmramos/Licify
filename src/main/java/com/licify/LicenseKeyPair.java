package com.licify;

import com.licify.signing.SignatureConfig;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

/**
 * Clase que encapsula un par de claves criptográficas (pública y privada)
 * para uso en la generación y validación de licencias.
 */
public class LicenseKeyPair {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    
    private final KeyPair keyPair;

    /**
     * Constructor privado. Use los métodos estáticos para crear instancias.
     */
    private LicenseKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /**
     * Genera un par de claves RSA
     */
    public static KeyPair generateRSAKeys(final int keySize) throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    /**
     * Genera un par de claves RSA con configuración personalizada
     */
    public static KeyPair generateRSAKeys(final SignatureConfig config) throws Exception {
        return generateRSAKeys(config.getKeySize());
    }

    /**
     * Genera una clave AES simétrica
     */
    public static SecretKey generateAESKey() throws Exception {
        final javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(256);
        return keyGen.generateKey();
    }

    public static KeyPair generateKeyPair(final SignatureConfig config) throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM, config.getProvider());
        keyGen.initialize(config.getKeySize());
        return keyGen.generateKeyPair();
    }
    
    /**
     * Genera un nuevo par de claves RSA de 2048 bits por defecto.
     * @return Una nueva instancia de LicenseKeyPair
     * @throws Exception si falla la generación de claves
     */
    public static LicenseKeyPair generate() throws Exception {
        return generate(2048);
    }
    
    /**
     * Genera un nuevo par de claves RSA con el tamaño especificado.
     * @param keySize Tamaño de la clave en bits (ej. 2048, 4096)
     * @return Una nueva instancia de LicenseKeyPair
     * @throws Exception si falla la generación de claves
     */
    public static LicenseKeyPair generate(int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(keySize);
        return new LicenseKeyPair(keyGen.generateKeyPair());
    }
    
    /**
     * Obtiene la clave privada.
     * @return La clave privada
     */
    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }
    
    /**
     * Obtiene la clave pública.
     * @return La clave pública
     */
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
    
    /**
     * Obtiene el KeyPair subyacente.
     * @return El KeyPair de Java
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }
}
