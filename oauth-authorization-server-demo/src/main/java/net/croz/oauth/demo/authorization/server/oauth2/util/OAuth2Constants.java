package net.croz.oauth.demo.authorization.server.oauth2.util;

import org.togglz.core.Feature;
import org.togglz.core.util.NamedFeature;

public class OAuth2Constants {

    public static Feature OAUTH_FEATURE = new NamedFeature("OAUTH2");

    public static class ResponseTypes {
        public static final String CODE = "code";
        public static final String TOKEN = "token";
    }

}
