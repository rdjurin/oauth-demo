package net.croz.oauth.demo.authorization.server.endpoint;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.croz.oauth.demo.authorization.server.oauth.config.OAuthKeys;
import net.croz.oauth.demo.authorization.server.service.OAuthSession;
import net.croz.oauth.demo.authorization.server.service.OAuthSessionService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Date;
import java.time.Instant;
import java.util.Map;

@Controller
@RequestMapping("/oauth/token")
public class TokenController {

    private final OAuthKeys keys;

    private final OAuthSessionService sessionService;

    public TokenController(OAuthKeys keys, OAuthSessionService sessionService) {
        this.keys = keys;
        this.sessionService = sessionService;
    }

    @PostMapping()
    public void request(HttpServletRequest request, HttpServletResponse response) {

        Map<String, String[]> parameters = request.getParameterMap();

        String code = request.getParameter("code");
        OAuthSession session = sessionService.findByAuthorizationCode(code);

        if (session == null) {
            throw new RuntimeException("Session is not exists for authorization code");
        }
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.parse(keys.getAlgorithm()))
                .keyID(keys.getKeyId())
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("demo-server")//TOOD
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(60 * 5))) //TODO
                .jwtID(new JWTID().getValue())
                .subject("demo2")
                .audience(session.getClientId())
                .claim("azp", session.getClientId())
                .claim("email", "demo2.user@test.hr")
                .claim("name", "Demo User")
                .claim("given_name", "Demo")
                .claim("family_name", "User")
                .claim("nonce", session.getNonce())
                .build();


        SignedJWT idToken = new SignedJWT(header, claims);

        JWSSigner signer = new RSASSASigner(keys.getPrivateKey());
        try {
            idToken.sign(signer);
        } catch (JOSEException e) {
            e.printStackTrace(); // TODO
        }


        AccessToken accessToken = new BearerAccessToken(idToken.serialize(), 3600L, null);

        OIDCTokens oidcTokens = new OIDCTokens(idToken, accessToken, null);
        AccessTokenResponse tokenResponse = new OIDCTokenResponse(oidcTokens);

        //TokenResponse tokenResponse = new AccessTokenResponse(new Tokens(accessToken, null));

        writeAccessToken(tokenResponse, response);


    }

    private void writeAccessToken(AccessTokenResponse accessTokenResponse, HttpServletResponse response) {
        response.addHeader("Content-Type", "application/json");
        response.addHeader("Cache-Control", "no-store");
        response.addHeader("Pragma", "no-cache");

        PrintWriter writer = null;
        try {
            writer = response.getWriter();
            accessTokenResponse.toJSONObject().writeJSONString(writer);
            writer.flush();
            writer.close();
            response.flushBuffer();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (writer != null) {
                writer.close();
            }
        }
    }


}
