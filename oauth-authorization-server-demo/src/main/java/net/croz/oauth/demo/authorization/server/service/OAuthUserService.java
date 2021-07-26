package net.croz.oauth.demo.authorization.server.service;

import lombok.Builder;
import lombok.Value;
import net.croz.oauth.demo.authorization.server.oauth.exception.UserNotAuthenticatedException;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public interface OAuthUserService {

    @Value
    @Builder
    class TokenClaims {
        private Map<String, Object> idTokenClaims;
        private Map<String, Object> accessTokenClaims;
    }

    TokenClaims resolveClaims(HttpServletRequest request) throws UserNotAuthenticatedException;

}
