package net.croz.oauth.demo.authorization.server.oauth2.model;

import lombok.Builder;
import lombok.Value;

import java.util.Map;

@Value
@Builder
public class TokenClaims {
    private Map<String, Object> idTokenClaims;
    private Map<String, Object> accessTokenClaims;
}
