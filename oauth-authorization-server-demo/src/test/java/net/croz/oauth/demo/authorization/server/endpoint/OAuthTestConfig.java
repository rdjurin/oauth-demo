package net.croz.oauth.demo.authorization.server.endpoint;

import net.croz.oauth.demo.authorization.server.oauth.config.OAuthConfiguration;
import net.croz.oauth.demo.authorization.server.oauth.config.OAuthKeys;
import net.croz.oauth.demo.authorization.server.oauth.config.OAuthProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@TestConfiguration
@EnableConfigurationProperties(OAuthProperties.class)
public class OAuthTestConfig {

    @Bean
    public OAuthKeys oAuthKeys(OAuthProperties oAuthProperties) {
        return new OAuthConfiguration().oAuthKeys(oAuthProperties);
    }

}
