package net.croz.oauth.demo.authorization.server.oauth.config;

import net.croz.oauth.demo.authorization.server.oauth.util.RSAUtil;
import net.croz.oauth.demo.authorization.server.service.DummyOAuthUserService;
import net.croz.oauth.demo.authorization.server.service.OAuthSessionService;
import net.croz.oauth.demo.authorization.server.service.OAuthUserService;
import net.croz.oauth.demo.authorization.server.service.impl.InMemoryOAuthSessionService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Objects;
import java.util.Optional;

@Configuration
@EnableConfigurationProperties(OAuthProperties.class)
public class OAuthConfiguration {

    @Bean
    public OAuthKeys oAuthKeys(OAuthProperties properties) {
        OAuthProperties.JWKKeys jwk = Objects.requireNonNull(properties.getJwk(), "oauth.jwk configuration must exists.");

        return OAuthKeys.builder()
                .keyId(Objects.requireNonNull(jwk.getKeyId(), "oauth.jwk.key-id must exists."))
                .algorithm(Objects.requireNonNull(jwk.getAlgorithm(), "oauth.jwk.algorithm must exists."))
                .publicKey(
                        RSAUtil.readPublicKey(
                                Optional.of(jwk)
                                        .map(OAuthProperties.JWKKeys::getPublicKey)
                                        .orElseThrow(() -> new IllegalArgumentException("oauth.jwk.publicKey must exists."))
                        )
                )
                .privateKey(
                        RSAUtil.readPrivateKey(
                                Optional.of(jwk)
                                        .map(OAuthProperties.JWKKeys::getPrivateKey)
                                        .orElseThrow(() -> new IllegalArgumentException("oauth.jwk.privateKey must exists."))
                        ))
                .build();
    }

    @Bean
    public OAuthSessionService oAuthSessionService() {
        return new InMemoryOAuthSessionService();
    }

    @Bean
    public OAuthUserService oAuthUserService() {
        return new DummyOAuthUserService();
    }
}
