package com.licify;

import com.licify.signing.SignatureConfig;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.SecretKey;

public class LicenseKeyPair {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";

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
}
