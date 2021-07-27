package net.croz.oauth.demo.authorization.server.oauth2.service.impl;

import net.croz.oauth.demo.authorization.server.oauth2.model.OAuth2Session;
import net.croz.oauth.demo.authorization.server.oauth2.service.OAuth2SessionService;

import java.util.HashMap;
import java.util.Map;

public class InMemoryOAuth2SessionService implements OAuth2SessionService {

    private final Map<String, OAuth2Session> sessions = new HashMap<>();

    @Override
    public OAuth2Session save(OAuth2Session session) {
        sessions.put(session.getId(), session);
        return session;
    }

    @Override
    public OAuth2Session findById(String id) {
        return sessions.get(id);
    }

    @Override
    public OAuth2Session findByAuthorizationCode(String authorizationCode) {
        return sessions.values()
                .stream()
                .filter(s -> authorizationCode.equals(s.getAuthorizationCode()))
                .findFirst()
                .orElse(null);
    }
}
