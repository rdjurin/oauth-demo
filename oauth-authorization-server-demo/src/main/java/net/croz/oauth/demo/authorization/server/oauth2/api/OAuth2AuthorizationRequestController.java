package net.croz.oauth.demo.authorization.server.oauth2.api;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import net.croz.oauth.demo.authorization.server.oauth2.config.OAuth2Keys;
import net.croz.oauth.demo.authorization.server.oauth2.config.OAuth2Properties;
import net.croz.oauth.demo.authorization.server.oauth2.exception.InvalidParameterException;
import net.croz.oauth.demo.authorization.server.oauth2.exception.InvalidRequestException;
import net.croz.oauth.demo.authorization.server.oauth2.exception.NotEnabledException;
import net.croz.oauth.demo.authorization.server.oauth2.model.OAuth2ErrorType;
import net.croz.oauth.demo.authorization.server.oauth2.model.OAuth2Session;
import net.croz.oauth.demo.authorization.server.oauth2.model.TokenClaims;
import net.croz.oauth.demo.authorization.server.oauth2.util.OAuth2Constants;
import net.croz.oauth.demo.authorization.server.oauth2.service.OAuth2SessionService;
import net.croz.oauth.demo.authorization.server.oauth2.service.OAuth2ClaimsService;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;
import org.togglz.core.manager.FeatureManager;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.*;

@Controller
@RequestMapping("/oauth/auth")
public class OAuth2AuthorizationRequestController extends AbstractOAuth2ControllerSupport {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2AuthorizationRequestController.class);

    private final OAuth2Keys keys;
    private final OAuth2SessionService oauthSessionService;
    private final OAuth2Properties properties;
    private final OAuth2ClaimsService oAuthUserService;

    public OAuth2AuthorizationRequestController(OAuth2Keys keys, OAuth2SessionService oauthSessionService, OAuth2ClaimsService oAuthUserService,
                                                OAuth2Properties properties, FeatureManager featureManager) {
        super(featureManager);
        this.keys = keys;
        this.oAuthUserService = oAuthUserService;
        this.oauthSessionService = oauthSessionService;
        this.properties = properties;
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(InvalidRequestException.class)
    public void handleInvalidRequestException() {

    }

    @GetMapping()
    public ModelAndView request(HttpServletRequest httpRequest, @RequestParam Map<String, String> requestParams) {

        if (!isEnabled()) {
            LOGGER.warn("[oAuth2] oAuth2 request receive from: {} with params: {}, but oAuth functionality is disabled.", httpRequest.getRemoteAddr(), requestParams);
            throw new NotEnabledException("OAuth2 feature is disabled");
        }


        LOGGER.debug("[oAuth2] authorization request received from {} with query params: {} ", httpRequest.getRemoteAddr(), requestParams);

        OAuth2Session session = createSessionFromParameters(requestParams);

        LOGGER.debug("[oAuth2] session created with id: {} and data: {}", session.getId(), session);
        LOGGER.info("[oAuth2] session created with id: {} for clientId: {} and validation started.", session.getId(), session.getClientId());

        //validate client and redirect uri
        OAuth2Properties.OAuthClient oAuthClient = resolveClient(session);
        validateRedirectUri(oAuthClient, session);

        //validate other parameters
        try {
            validateState(session);
            validateScope(oAuthClient, session);
            validateResponseType(session);
            validateNonce(session);
            validateCodeChallenge(oAuthClient, session);
            //validateRequest(oAuthClient, session)
        } catch (InvalidParameterException e) {
            Map<String, String> attributes = new LinkedHashMap<>();
            attributes.put("error", e.getErrorType().name());
            attributes.put("error_description", e.getMessage());
            if (!"state".equals(e.getParameter())) {
                attributes.put("state", session.getState());
            }
            return new ModelAndView(String.format("redirect:%s", session.getRedirectUri()), attributes);
        }

        try {
            LOGGER.info("[oAuth2] session validation is sucess for id: {}. Generating authorization code and tokens for user data.", session.getId());

            //create idToken, accessToken and refreshToken
            LOGGER.debug("[oAuth2] Resolving claims from user service for oAuth session: {}", session.getId());
            TokenClaims tokenClaims;
            try {
                tokenClaims = oAuthUserService.resolveClaims(httpRequest);
            } catch (Exception e) {
                return redirectToLogin(session, httpRequest.getRequestURL().toString(), requestParams);
            }
            LOGGER.debug("[oAuth2] Resolved claims from user service for oAuth session: {} with claims: {}", session.getId(), tokenClaims);

            //Id token
            JWTClaimsSet idTokenClaims = jwtClaims(session, tokenClaims.getIdTokenClaims());
            PlainJWT idTokenPlain = new PlainJWT(idTokenClaims);
            session.setIdTokenPlain(idTokenPlain.serialize());

            //Access token
            JWTClaimsSet accessTokenClaims = jwtClaims(session, tokenClaims.getAccessTokenClaims());
            PlainJWT accessTokenPlain = new PlainJWT(accessTokenClaims);
            session.setAccessTokenPlain(accessTokenPlain.serialize());

            //refresh token
            RefreshToken refreshToken = new RefreshToken();
            session.setRefreshToken(refreshToken.getValue());

            //generate authorization code and send response
            AuthorizationCode authorizationCode = new AuthorizationCode();
            session.setAuthorizationCode(authorizationCode.getValue());
            session.setAuthorizationCodeLifetime(oAuthClient.getAuthorizationCodeLifetime());
            session.setAuthorizationCodeIssuedAt(Instant.now());

            session.setStatus(OAuth2Session.Status.AUTHORIZATION_CODE_ISSUED);

            LOGGER.info("[oAuth] saved session with id: {}", session.getId());
            oauthSessionService.save(session);

            Map<String, String> attributes = new HashMap<>();
            attributes.put("code", session.getAuthorizationCode());

            if (StringUtils.isNotBlank(session.getState())) {
                attributes.put("state", session.getState());
            }
            return new ModelAndView(String.format("redirect:%s", session.getRedirectUri()), attributes);
        } catch (Exception e) {
            LOGGER.error("[oAuth] Error id: {}", session.getId(), e);
            Map<String, String> attributes = new LinkedHashMap<>();
            attributes.put("error", OAuth2ErrorType.server_error.name());
            attributes.put("error_description", "Internal error occured when processing authorization request. Error ref: ");
            if (session.getState() != null) {
                attributes.put("state", session.getState());
            }
            return new ModelAndView(String.format("redirect:%s", session.getRedirectUri()), attributes);
        }
    }

    private OAuth2Session createSessionFromParameters(Map<String, String> requestParams) {
        String clientId = requestParams.get("client_id");
        String redirectUri = requestParams.get("redirect_uri");
        String scope = requestParams.get("scope");
        String responseType = requestParams.get("response_type");
        String state = requestParams.get("state");
        String nonce = requestParams.get("nonce");
        String request = requestParams.get("request");
        String codeChallenge = requestParams.get("code_challenge");
        String codeChallengeMethod = requestParams.get("code_challenge_method");

        OAuth2Session session = OAuth2Session.builder()
                .id(UUID.randomUUID().toString())
                .created(Instant.now())
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scope(scope)
                .responseType(responseType)
                .state(state)
                .nonce(nonce)
                .request(request)
                .codeChallenge(codeChallenge)
                .codeChallengeMethod(codeChallengeMethod)
                .build();
        return session;
    }

    private ModelAndView redirectToLogin(OAuth2Session session, String requestUrl, Map<String, String> requestParams) {

        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(requestUrl);
        for (Map.Entry<String, String> param : requestParams.entrySet()) {
            uriComponentsBuilder.queryParam(param.getKey(), param.getValue());
        }

        String requestUri = uriComponentsBuilder.build().toString();

        String loginRedirectUri = this.properties.getLoginRedirectUri();
        String redirectTo = String.format(loginRedirectUri, requestUri);
        return new ModelAndView(String.format("redirect:%s", redirectTo));

    }

    private JWTClaimsSet jwtClaims(OAuth2Session session, Map<String, Object> claims) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(this.properties.getIssuer())
                .jwtID(new JWTID().getValue())
                .audience(session.getClientId())
                .claim("azp", session.getClientId());

        if (session.getNonce() != null) {
            builder.claim("nonce", session.getNonce());
        }

        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            if ("sub".equals(entry.getKey())) {
                builder.subject((String) entry.getValue());
            }
            builder.claim(entry.getKey(), entry.getValue());
        }

        return builder.build();

    }

    private OAuth2Properties.OAuthClient resolveClient(OAuth2Session session) {
        String clientId = session.getClientId();
        if (StringUtils.isBlank(clientId)) {
            throw new InvalidRequestException("client_id parameter is missing");
        }

        OAuth2Properties.OAuthClient oAuthClient = this.properties.getClients().get(clientId);
        if (oAuthClient == null || !clientId.equals(oAuthClient.getClientId())) {
            throw new InvalidRequestException("Client with client_id not exist");
        }

        return oAuthClient;
    }

    private void validateRedirectUri(OAuth2Properties.OAuthClient client, OAuth2Session session) {
        String redirectUri = session.getRedirectUri();
        if (StringUtils.isBlank(redirectUri)) {
            throw new InvalidRequestException("redirect_uri parameter is missing");
        }

        if (!client.getRedirectUris().contains(redirectUri)) {
            throw new InvalidRequestException("Redirect uri not matches client redirectUris");
        }
    }

    private void validateState(OAuth2Session session) throws InvalidParameterException {
        if (StringUtils.isBlank(session.getState())) {
            throw InvalidParameterException.invalidRequest("state", "state parameter is missing");
        }
    }

    private void validateScope(OAuth2Properties.OAuthClient client, OAuth2Session session) throws InvalidParameterException {
        String scope = session.getScope();
        if (StringUtils.isBlank(scope)) {
            throw InvalidParameterException.invalidScope("scope", "scope parameter is missing");
        }
        String[] scopes = StringUtils.split(scope, ' ');

        if (!Arrays.stream(scopes).allMatch(s -> client.getScopes().contains(s))) {
            throw InvalidParameterException.invalidScope("scope", "Provided scopes not matches client scopes.");
        };
    }

    private void validateResponseType(OAuth2Session session) throws InvalidParameterException {
        String responseType = session.getResponseType();
        if (StringUtils.isBlank(responseType)) {
            throw InvalidParameterException.invalidRequest("response_type", "response_type parameter is missing");
        }

        if (!OAuth2Constants.ResponseTypes.CODE.equals(responseType)) {
            throw InvalidParameterException.unsupportedResponseType("response_type", "Invalid response_type parameter value.");
        }
    }

    private void validateNonce(OAuth2Session session) throws InvalidParameterException {
        if (StringUtils.isBlank(session.getNonce())) {
            throw InvalidParameterException.invalidRequest("nonce", "nonce parameter is missing");
        }
    }

    private void validateCodeChallenge(OAuth2Properties.OAuthClient client, OAuth2Session session) throws InvalidParameterException {
        if (client.getPkceMethod() != null) {
            String codeChallenge = session.getCodeChallenge();
            String codeChallengeMethod = session.getCodeChallengeMethod();
            if (StringUtils.isBlank(codeChallenge)) {
                throw InvalidParameterException.invalidRequest("code_challenge", "code_challenge parameter is missing");
            }
            if (StringUtils.isBlank(codeChallengeMethod)) {
                throw InvalidParameterException.invalidRequest("code_challenge_method", "code_challenge_method parameter is missing");
            }
            if (!client.getPkceMethod().equals(codeChallengeMethod)) {
                throw InvalidParameterException.invalidRequest("code_challenge_method", "Provided code_challenge_method has invalid value.");
            }
        }

    }

}
