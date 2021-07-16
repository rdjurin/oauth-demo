package net.croz.oauth.demo.resource.api;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import net.croz.oauth.demo.resource.util.RSAUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
import java.util.Map;

@RestController
public class JwksController {

    private final RSAPublicKey publicKey;
    private final JWKSet jwkSet;

    public JwksController(@Value("${jwk.public}")String publicKey) {
        this.publicKey = RSAUtil.readPublicKey(publicKey);
        this.jwkSet = new JWKSet(new RSAKey.Builder(this.publicKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS512)
                .keyID("demo")
                .build()
        );
    }

    @GetMapping("/api/jwks")
    public Map<String, Object> keys() {
        return this.jwkSet.toJSONObject();
    }
}
