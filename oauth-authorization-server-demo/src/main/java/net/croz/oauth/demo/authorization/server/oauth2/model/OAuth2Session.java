package net.croz.oauth.demo.authorization.server.oauth2.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuth2Session {

    public enum Status {
        AUTHORIZATION_CODE_ISSUED, //authorization code issued
        ACCESS_TOKEN_ISSUED, // tokens issued
        INVALID // session closed or expired
    }

    private String id;
    private Instant created;
    private Status status;

    //Authorization request parameters
    private String clientId;
    private String responseType;
    private String redirectUri;
    private String scope;
    private String state;
    private String nonce;
    private String request;
    private String codeChallenge;
    private String codeChallengeMethod;

    //authorization code data
    private String authorizationCode;
    private Instant authorizationCodeIssuedAt;
    private Integer authorizationCodeLifetime;

    //tokens data
    private String idTokenPlain;
    private String accessTokenPlain;
    private String idToken;
    private String accessToken;
    private String refreshToken;
    private Instant tokenIssuedAt;
    private Instant tokenExpirationTime;
    private Instant tokenNotBeforeTime;
    private Integer tokenCodeLifetime;


}
