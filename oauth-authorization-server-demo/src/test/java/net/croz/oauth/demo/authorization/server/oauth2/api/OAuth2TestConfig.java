package net.croz.oauth.demo.authorization.server.oauth2.api;

import net.croz.oauth.demo.authorization.server.oauth2.config.OAuth2Configuration;
import net.croz.oauth.demo.authorization.server.oauth2.config.OAuth2Keys;
import net.croz.oauth.demo.authorization.server.oauth2.config.OAuth2Properties;
import net.croz.oauth.demo.authorization.server.oauth2.util.OAuth2Constants;
import org.mockito.Mockito;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.togglz.core.manager.FeatureManager;

@TestConfiguration
@EnableConfigurationProperties(OAuth2Properties.class)
public class OAuth2TestConfig {

    @Bean
    public OAuth2Keys oAuth2Keys(OAuth2Properties oAuthProperties) {
        FeatureManager featureManager = Mockito.mock(FeatureManager.class);
        Mockito.when(featureManager.isActive(OAuth2Constants.OAUTH_FEATURE)).thenReturn(true);
        return new OAuth2Configuration(featureManager).oAuthKeys(oAuthProperties);
    }

}
