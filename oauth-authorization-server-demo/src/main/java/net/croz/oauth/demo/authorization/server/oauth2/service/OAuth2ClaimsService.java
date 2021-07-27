package net.croz.oauth.demo.authorization.server.oauth2.service;

import net.croz.oauth.demo.authorization.server.oauth2.exception.UserNotAuthenticatedException;
import net.croz.oauth.demo.authorization.server.oauth2.model.TokenClaims;

import javax.servlet.http.HttpServletRequest;

public interface OAuth2ClaimsService {

    TokenClaims resolveClaims(HttpServletRequest request) throws UserNotAuthenticatedException;

}
