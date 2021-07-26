package net.croz.oauth.demo.authorization.server.service;

import net.croz.oauth.demo.authorization.server.oauth.exception.UserNotAuthenticatedException;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public class DummyOAuthUserService implements OAuthUserService {

    @Override
    public TokenClaims resolveClaims(HttpServletRequest request) throws UserNotAuthenticatedException {
        return new TokenClaims(
                Map.of("sub", "test"),
                Map.of("company_id", "Company")
        );
    }
}
