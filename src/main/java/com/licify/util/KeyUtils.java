package com.licify.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyUtils {

    public static PublicKey loadPublicKeyFromResource(String resourcePath) {
        // Primero intentar cargar desde recursos (classpath)  
        try (InputStream is = KeyUtils.class.getResourceAsStream(resourcePath)) {
            if (is != null) {
                return loadPublicKeyFromStream(is);
            }
        } catch (Exception e) {
            System.err.println("No se pudo cargar desde recursos: " + e.getMessage());
        }

        // Fallback: intentar cargar desde sistema de archivos  
        String filename = resourcePath.startsWith("/") ? resourcePath.substring(1) : resourcePath;
        Path filePath = Paths.get(filename);

        if (Files.exists(filePath)) {
            try {
                String pem = readFileToString(filePath);
                return loadPublicKeyFromPemString(pem);
            } catch (Exception e) {
                System.err.println("Error cargando desde archivo: " + e.getMessage());
            }
        }

        System.err.println("No se encontró la clave pública en recursos ni en sistema de archivos: " + resourcePath);
        return null;
    }

    private static PublicKey loadPublicKeyFromStream(InputStream is) throws Exception {
        String pem = inputStreamToString(is);
        return loadPublicKeyFromPemString(pem);
    }

    private static PublicKey loadPublicKeyFromPemString(String pem) throws Exception {
        String base64 = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(base64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(decoded));
    }

    /**
     * Carga una clave pública desde un archivo
     */
    public static PublicKey loadPublicKeyFromFile(String filename) throws Exception {
        String pem = readFileToString(Paths.get(filename));
        String base64 = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(base64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(decoded));
    }

    /**
     * Lee un archivo como string (compatible con Java 8)
     */
    private static String readFileToString(Path filePath) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = Files.newBufferedReader(filePath)) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }

    /**
     * Convierte InputStream a string (compatible con Java 8)
     */
    private static String inputStreamToString(InputStream is) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }
}
