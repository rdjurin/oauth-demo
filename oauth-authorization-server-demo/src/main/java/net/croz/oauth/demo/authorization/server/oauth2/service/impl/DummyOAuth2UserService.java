package net.croz.oauth.demo.authorization.server.oauth2.service.impl;

import net.croz.oauth.demo.authorization.server.oauth2.exception.UserNotAuthenticatedException;
import net.croz.oauth.demo.authorization.server.oauth2.model.TokenClaims;
import net.croz.oauth.demo.authorization.server.oauth2.service.OAuth2ClaimsService;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public class DummyOAuth2UserService implements OAuth2ClaimsService {

    @Override
    public TokenClaims resolveClaims(HttpServletRequest request) throws UserNotAuthenticatedException {
        return TokenClaims.builder()
                .idTokenClaims(Map.of("sub", "test"))
                .accessTokenClaims(Map.of("company_id", "Company"))
                .build();
    }
}
