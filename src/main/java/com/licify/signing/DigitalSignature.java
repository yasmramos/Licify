package com.licify.signing;

import java.security.*;
import java.util.Base64;

public class DigitalSignature {

    public static String signSHA512(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public static boolean verifySHA512(String data, String signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA512withRSA");
        sig.initVerify(publicKey);
        sig.update(data.getBytes());
        return sig.verify(Base64.getDecoder().decode(signature));
    }
}

