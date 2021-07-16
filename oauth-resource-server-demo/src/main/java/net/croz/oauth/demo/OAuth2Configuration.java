package net.croz.oauth.demo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import net.croz.oauth.demo.util.RSAUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.function.Function;

@Configuration
public class OAuth2Configuration extends WebSecurityConfigurerAdapter {


    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final Function<ClientRegistration, JWK> jwkResolver;

    public OAuth2Configuration(@Value("${jwk.private}") String privateKey, @Value("${jwk.public}")String publicKey) {
        this.privateKey = RSAUtil.readPrivateKey(privateKey);
        this.publicKey = RSAUtil.readPublicKey(publicKey);
        jwkResolver = (clientRegistration) -> {
            if (clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
                return new RSAKey.Builder(this.publicKey)
                        .privateKey(this.privateKey)
                        .keyID("demo")
                        .algorithm(JWSAlgorithm.RS512)
                        .keyUse(KeyUse.SIGNATURE)
                        .build();
            }
            return null;
        };
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        OAuth2AuthorizationCodeGrantRequestEntityConverter requestEntityConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
        requestEntityConverter.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver));

        DefaultAuthorizationCodeTokenResponseClient tokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        tokenResponseClient.setRequestEntityConverter(requestEntityConverter);

        http.antMatcher("/**").authorizeRequests()
                .antMatchers("/", "/login**", "/api/jwks**").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .tokenEndpoint()
                .accessTokenResponseClient(tokenResponseClient);

    }

}
