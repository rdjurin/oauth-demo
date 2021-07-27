package net.croz.oauth.demo.authorization.server.oauth2.service;

import net.croz.oauth.demo.authorization.server.oauth2.model.OAuth2Session;

public interface OAuth2SessionService {

    OAuth2Session save(OAuth2Session session);

    OAuth2Session findById(String id);

    OAuth2Session findByAuthorizationCode(String authorizationCode);

}
