package net.croz.oauth.demo.authorization.server.service;

public interface OAuthSessionService {

    OAuthSession save(OAuthSession session);

    OAuthSession findById(String id);

    OAuthSession findByAuthorizationCode(String authorizationCode);

}
