package net.croz.oauth.demo.authorization.server.oauth.config;

import lombok.*;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;
import java.util.Set;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ConfigurationProperties(prefix = "oauth")
public class OAuthProperties {

    private String issuer;
    private Map<String, OAuthClient> clients;
    private JWKKeys jwk;
    private String loginRedirectUri;

    @Getter
    @Setter
    public static class JWKKeys {
        private String keyId;
        private String algorithm;
        private String privateKey;
        private String publicKey;
    }

    @Getter
    @Setter
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class OAuthClient {
        private static final Integer DEFAULT_AUTHORIZATION_CODE_LIFETIME = 5 * 60; //5 minutes
        private static final Integer DEFAULT_ACCESS_TOKEN_LIFETIME = 15 * 60; // 30 minutes
        private String clientId;
        private Set<String> redirectUris;
        private Set<String> scopes;
        private String jwksUrl;
        private String pkceMethod;
        private Integer authorizationCodeLifetime = DEFAULT_AUTHORIZATION_CODE_LIFETIME;
        private Integer accessTokenLifetime = DEFAULT_ACCESS_TOKEN_LIFETIME;
    }

}
