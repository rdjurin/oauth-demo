package net.croz.oauth.demo.authorization.server.oauth.util;


import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtil {

    public static String cleanPEMHeaders(String key) {
        return key.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "");
    }

    public static RSAPublicKey readPublicKey(String publicKeyPem) {
        try {
            String key = cleanPEMHeaders(publicKeyPem);
            byte[] encoded = Base64.getDecoder().decode(key);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static RSAPrivateKey readPrivateKey(String privateKeyPem) {
        try {
            String key = cleanPEMHeaders(privateKeyPem);
            byte[] encoded = Base64.getDecoder().decode(key);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(encoded);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpecPKCS8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
