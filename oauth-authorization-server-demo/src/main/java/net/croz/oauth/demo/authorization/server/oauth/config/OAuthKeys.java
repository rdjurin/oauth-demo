package net.croz.oauth.demo.authorization.server.oauth.config;

import lombok.Builder;
import lombok.Value;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Value
@Builder
public class OAuthKeys {

    private final String keyId;
    private final String algorithm;
    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

}
