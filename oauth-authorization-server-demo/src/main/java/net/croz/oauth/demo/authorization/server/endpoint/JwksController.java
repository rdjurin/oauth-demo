package net.croz.oauth.demo.authorization.server.endpoint;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import net.croz.oauth.demo.authorization.server.oauth.config.OAuthKeys;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class JwksController {

    private final JWKSet jwkSet;

    public JwksController(OAuthKeys oAuthKeys) {
        this.jwkSet = new JWKSet(new RSAKey.Builder(oAuthKeys.getPublicKey())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.parse(oAuthKeys.getAlgorithm()))
                .keyID(oAuthKeys.getKeyId())
                .build()
        );
    }

    @GetMapping("/oauth/certs")
    public Map<String, Object> keys() {
        return this.jwkSet.toJSONObject();
    }
}

