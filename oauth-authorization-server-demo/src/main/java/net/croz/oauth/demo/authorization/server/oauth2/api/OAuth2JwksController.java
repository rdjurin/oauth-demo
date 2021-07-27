package net.croz.oauth.demo.authorization.server.oauth2.api;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import net.croz.oauth.demo.authorization.server.oauth2.config.OAuth2Keys;
import net.croz.oauth.demo.authorization.server.oauth2.exception.NotEnabledException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.togglz.core.manager.FeatureManager;

import java.util.Map;

@RestController
public class OAuth2JwksController extends AbstractOAuth2ControllerSupport {

    private final JWKSet jwkSet;

    public OAuth2JwksController(FeatureManager featureManager, OAuth2Keys oAuthKeys) {
        super(featureManager);
        if (isEnabled()) {
            this.jwkSet = new JWKSet(new RSAKey.Builder(oAuthKeys.getPublicKey())
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.parse(oAuthKeys.getAlgorithm()))
                    .keyID(oAuthKeys.getKeyId())
                    .build()
            );
        } else {
            this.jwkSet = null;
        }
    }

    @GetMapping("/oauth/certs")
    public Map<String, Object> keys() {
        if (!isEnabled()) {
            throw new NotEnabledException("OAuth2 feature is disabled");
        }
        return this.jwkSet.toJSONObject();
    }
}

