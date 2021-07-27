package net.croz.oauth.demo.authorization.server.oauth2.api;

import net.croz.oauth.demo.authorization.server.oauth2.exception.NotEnabledException;
import net.croz.oauth.demo.authorization.server.oauth2.util.OAuth2Constants;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.togglz.core.manager.FeatureManager;

public abstract class AbstractOAuth2ControllerSupport {

    private final FeatureManager featureManager;

    public AbstractOAuth2ControllerSupport(FeatureManager featureManager) {
        this.featureManager = featureManager;
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(NotEnabledException.class)
    public void handleNotEnabled() {

    }

    protected boolean isEnabled() {
        return this.featureManager.isActive(OAuth2Constants.OAUTH_FEATURE);
    }
}
