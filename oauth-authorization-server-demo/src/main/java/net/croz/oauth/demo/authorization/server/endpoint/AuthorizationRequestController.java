package net.croz.oauth.demo.authorization.server.endpoint;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import net.croz.oauth.demo.authorization.server.oauth.config.OAuthKeys;
import net.croz.oauth.demo.authorization.server.oauth.config.OAuthProperties;
import net.croz.oauth.demo.authorization.server.oauth.exception.InvalidParameterException;
import net.croz.oauth.demo.authorization.server.oauth.exception.InvalidRequestException;
import net.croz.oauth.demo.authorization.server.oauth.model.OAuth2ErrorType;
import net.croz.oauth.demo.authorization.server.oauth.util.OAuth2Constants;
import net.croz.oauth.demo.authorization.server.service.OAuthSession;
import net.croz.oauth.demo.authorization.server.service.OAuthSessionService;
import net.croz.oauth.demo.authorization.server.service.OAuthUserService;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.*;

@Controller
@RequestMapping("/oauth/auth")
public class AuthorizationRequestController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationRequestController.class);

    private final OAuthKeys keys;
    private final OAuthSessionService oauthSessionService;
    private final OAuthProperties properties;
    private final OAuthUserService oAuthUserService;

    public AuthorizationRequestController(OAuthKeys keys, OAuthSessionService oauthSessionService, OAuthUserService oAuthUserService, OAuthProperties properties) {
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

        LOGGER.debug("[oAuth2] authorization request received from {} with query params: {} ", httpRequest.getRemoteAddr(), requestParams);

        String clientId = requestParams.get("client_id");
        String redirectUri = requestParams.get("redirect_uri");
        String scope = requestParams.get("scope");
        String responseType = requestParams.get("response_type");
        String state = requestParams.get("state");
        String nonce = requestParams.get("nonce");
        String request = requestParams.get("request");
        String codeChallenge = requestParams.get("code_challenge");
        String codeChallengeMethod = requestParams.get("code_challenge_method");

        OAuthSession session = OAuthSession.builder()
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

        LOGGER.debug("[oAuth2] session created with id: {} and data: {}", session.getId(), session);
        LOGGER.info("[oAuth2] session created with id: {} for clientId: {} and validation started.", session.getId(), session.getClientId());

        //validate client and redirect uri
        OAuthProperties.OAuthClient oAuthClient = resolveClient(session);
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
                attributes.put("state", state);
            }
            return new ModelAndView(String.format("redirect:%s", redirectUri), attributes);
        }

        try {
            LOGGER.info("[oAuth2] session validation is sucess for id: {}. Generating authorization code and tokens for user data.", session.getId());

            //create idToken, accessToken and refreshToken
            LOGGER.debug("[oAuth2] Resolving claims from user service for oAuth session: {}", session.getId());
            OAuthUserService.TokenClaims tokenClaims;
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

            session.setStatus(OAuthSession.Status.PENDING);

            LOGGER.info("[oAuth] saved session with id: {}", session.getId());
            oauthSessionService.save(session);

            Map<String, String> attributes = new HashMap<>();
            attributes.put("code", session.getAuthorizationCode());

            if (StringUtils.isNotBlank(state)) {
                attributes.put("state", state);
            }

            return new ModelAndView(String.format("redirect:%s", redirectUri), attributes);
        } catch (Exception e) {
            LOGGER.error("[oAuth] Error id: {}", session.getId(), e);
            Map<String, String> attributes = new LinkedHashMap<>();
            attributes.put("error", OAuth2ErrorType.server_error.name());
            attributes.put("error_description", "Internal error occured when processing authorization request. Error ref: ");
            if (session.getState() != null) {
                attributes.put("state", state);
            }
            return new ModelAndView(String.format("redirect:%s", redirectUri), attributes);
        }
    }

    private ModelAndView redirectToLogin(OAuthSession session, String requestUrl, Map<String, String> requestParams) {

        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(requestUrl);
        for (Map.Entry<String, String> param : requestParams.entrySet()) {
            uriComponentsBuilder.queryParam(param.getKey(), param.getValue());
        }

        String requestUri = uriComponentsBuilder.build().toString();

        String loginRedirectUri = this.properties.getLoginRedirectUri();
        String redirectTo = String.format(loginRedirectUri, requestUri);
        return new ModelAndView(String.format("redirect:%s", redirectTo));

    }

    private JWTClaimsSet jwtClaims(OAuthSession session, Map<String, Object> claims) {
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

    private OAuthProperties.OAuthClient resolveClient(OAuthSession session) {
        String clientId = session.getClientId();
        if (StringUtils.isBlank(clientId)) {
            throw new InvalidRequestException("client_id parameter is missing");
        }

        OAuthProperties.OAuthClient oAuthClient = this.properties.getClients().get(clientId);
        if (oAuthClient == null || !clientId.equals(oAuthClient.getClientId())) {
            throw new InvalidRequestException("Client with client_id not exist");
        }

        return oAuthClient;
    }

    private void validateRedirectUri(OAuthProperties.OAuthClient client, OAuthSession session) {
        String redirectUri = session.getRedirectUri();
        if (StringUtils.isBlank(redirectUri)) {
            throw new InvalidRequestException("redirect_uri parameter is missing");
        }

        if (!client.getRedirectUris().contains(redirectUri)) {
            throw new InvalidRequestException("Redirect uri not matches client redirectUris");
        }
    }

    private void validateState(OAuthSession session) throws InvalidParameterException {
        if (StringUtils.isBlank(session.getState())) {
            throw InvalidParameterException.invalidRequest("state", "state parameter is missing");
        }
    }

    private void validateScope(OAuthProperties.OAuthClient client, OAuthSession session) throws InvalidParameterException {
        String scope = session.getScope();
        if (StringUtils.isBlank(scope)) {
            throw InvalidParameterException.invalidScope("scope", "scope parameter is missing");
        }
        String[] scopes = StringUtils.split(scope, ',');

        if (!Arrays.stream(scopes).allMatch(s -> client.getScopes().contains(s))) {
            throw InvalidParameterException.invalidScope("scope", "Provided scopes not matches client scopes.");
        };
    }

    private void validateResponseType(OAuthSession session) throws InvalidParameterException {
        String responseType = session.getResponseType();
        if (StringUtils.isBlank(responseType)) {
            throw InvalidParameterException.invalidRequest("response_type", "response_type parameter is missing");
        }

        if (!OAuth2Constants.ResponseTypes.CODE.equals(responseType)) {
            throw InvalidParameterException.unsupportedResponseType("response_type", "Invalid response_type parameter value.");
        }
    }

    private void validateNonce(OAuthSession session) throws InvalidParameterException {
        if (StringUtils.isBlank(session.getNonce())) {
            throw InvalidParameterException.invalidRequest("nonce", "nonce parameter is missing");
        }
    }

    private void validateCodeChallenge(OAuthProperties.OAuthClient client, OAuthSession session) throws InvalidParameterException {
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
