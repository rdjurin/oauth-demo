package net.croz.oauth.demo.authorization.server.service.impl;

import net.croz.oauth.demo.authorization.server.service.OAuthSession;
import net.croz.oauth.demo.authorization.server.service.OAuthSessionService;

import java.util.HashMap;
import java.util.Map;

public class InMemoryOAuthSessionService implements OAuthSessionService {

    private final Map<String, OAuthSession> sessions = new HashMap<>();

    @Override
    public OAuthSession save(OAuthSession session) {
        sessions.put(session.getId(), session);
        return session;
    }

    @Override
    public OAuthSession findById(String id) {
        return sessions.get(id);
    }

    @Override
    public OAuthSession findByAuthorizationCode(String authorizationCode) {
        return sessions.values()
                .stream()
                .filter(s -> authorizationCode.equals(s.getAuthorizationCode()))
                .findFirst()
                .orElse(null);
    }
}
