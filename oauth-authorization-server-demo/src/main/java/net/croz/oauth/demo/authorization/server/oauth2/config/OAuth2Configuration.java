package net.croz.oauth.demo.authorization.server.oauth2.config;

import net.croz.oauth.demo.authorization.server.oauth2.util.OAuth2Constants;
import net.croz.oauth.demo.authorization.server.oauth2.util.RSAUtil;
import net.croz.oauth.demo.authorization.server.oauth2.service.impl.DummyOAuth2UserService;
import net.croz.oauth.demo.authorization.server.oauth2.service.OAuth2SessionService;
import net.croz.oauth.demo.authorization.server.oauth2.service.OAuth2ClaimsService;
import net.croz.oauth.demo.authorization.server.oauth2.service.impl.InMemoryOAuth2SessionService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.togglz.core.manager.FeatureManager;

import java.util.Objects;
import java.util.Optional;

@Configuration
@EnableConfigurationProperties(OAuth2Properties.class)
public class OAuth2Configuration {

    private final FeatureManager featureManager;

    public OAuth2Configuration(FeatureManager featureManager) {
        this.featureManager = featureManager;
    }

    @Bean
    public OAuth2Keys oAuthKeys(OAuth2Properties properties) {
        if (!featureManager.isActive(OAuth2Constants.OAUTH_FEATURE)) {
            return OAuth2Keys.builder().build(); //return empty

        }

        OAuth2Properties.JWKKeys jwk = Objects.requireNonNull(properties.getJwk(), "oauth.jwk configuration must exists.");

        return OAuth2Keys.builder()
                .keyId(Objects.requireNonNull(jwk.getKeyId(), "oauth.jwk.key-id must exists."))
                .algorithm(Objects.requireNonNull(jwk.getAlgorithm(), "oauth.jwk.algorithm must exists."))
                .publicKey(
                        RSAUtil.readPublicKey(
                                Optional.of(jwk)
                                        .map(OAuth2Properties.JWKKeys::getPublicKey)
                                        .orElseThrow(() -> new IllegalArgumentException("oauth.jwk.publicKey must exists."))
                        )
                )
                .privateKey(
                        RSAUtil.readPrivateKey(
                                Optional.of(jwk)
                                        .map(OAuth2Properties.JWKKeys::getPrivateKey)
                                        .orElseThrow(() -> new IllegalArgumentException("oauth.jwk.privateKey must exists."))
                        ))
                .build();
    }

    @Bean
    public OAuth2SessionService oAuthSessionService() {
        return new InMemoryOAuth2SessionService();
    }

    @Bean
    public OAuth2ClaimsService oAuthUserService() {
        return new DummyOAuth2UserService();
    }
}
