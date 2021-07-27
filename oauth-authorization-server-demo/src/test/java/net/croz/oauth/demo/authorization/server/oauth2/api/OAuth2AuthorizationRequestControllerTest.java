package net.croz.oauth.demo.authorization.server.oauth2.api;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import net.croz.oauth.demo.authorization.server.oauth2.exception.UserNotAuthenticatedException;
import net.croz.oauth.demo.authorization.server.oauth2.model.OAuth2Session;
import net.croz.oauth.demo.authorization.server.oauth2.model.TokenClaims;
import net.croz.oauth.demo.authorization.server.oauth2.util.OAuth2Constants;
import net.croz.oauth.demo.authorization.server.oauth2.service.OAuth2SessionService;
import net.croz.oauth.demo.authorization.server.oauth2.service.OAuth2ClaimsService;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.togglz.core.manager.FeatureManager;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@ExtendWith(SpringExtension.class)
@WebMvcTest(controllers = OAuth2AuthorizationRequestController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(OAuth2TestConfig.class)
class OAuth2AuthorizationRequestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private OAuth2SessionService oAuthSessionService;

    @MockBean
    private OAuth2ClaimsService oAuthUserService;

    @MockBean
    private FeatureManager featureManager;

    @BeforeEach
    public void before() {
        Mockito.when(featureManager.isActive(OAuth2Constants.OAUTH_FEATURE)).thenReturn(true);
    }

    @Test
    public void whenOAuth2FeatureIsDisabled_expectNotFound() throws Exception  {
        Mockito.reset(featureManager);
        Mockito.when(featureManager.isActive(OAuth2Constants.OAUTH_FEATURE)).thenReturn(false);
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("redirect_uri", "http://test.test.hr/redirect")
                        .param("scope", "openid test")
                        .param("response_type", "code")

        ).andExpect(MockMvcResultMatchers.status().isNotFound());
    }


    @Test
    public void whenClientIdNotExists_expectInvalidRequest() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("redirect_uri", "http://test.test.hr/redirect")
                        .param("scope", "openid test")
                        .param("response_type", "code")

        ).andExpect(MockMvcResultMatchers.status().isBadRequest());

    }

    @Test
    public void whenClientWithRequestedClientIdNotExists_expectInvalidRequest() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "not-existing-client")
                        .param("redirect_uri", "http://test.test.hr/redirect")
                        .param("scope", "openid test")
                        .param("response_type", "code")

        ).andExpect(MockMvcResultMatchers.status().isBadRequest());

    }

    @Test
    public void whenRedirectUriNotExists_expectInvalidRequest() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("scope", "openid test")
                        .param("response_type", "code")

        ).andExpect(MockMvcResultMatchers.status().isBadRequest());

    }

    @Test
    public void whenClientNotContainsRedirectUri_expectInvalidRequest() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "http://test.test.hr/redirect")
                        .param("scope", "openid test")
                        .param("response_type", "code")

        ).andExpect(MockMvcResultMatchers.status().isBadRequest());

    }

    @Test
    public void whenStateNotExists_expectRedirectWithError() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://test.redirect.uri/test")
                        .param("response_type", "code")
                        .param("scope", "openid")

        )
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("https://test.redirect.uri/test" +
                        "?error=invalid_request&error_description=state+parameter+is+missing"));

    }

    @Test
    public void whenScopeNotExists_expectRedirectWithError() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://test.redirect.uri/test")
                        .param("state", "state123")
                        .param("response_type", "code")


        )
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("https://test.redirect.uri/test?" +
                        "error=invalid_scope&error_description=scope+parameter+is+missing&state=state123"));

    }

    @Test
    public void whenClientNotContainsScopes_expectRedirectWithError() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://test.redirect.uri/test")
                        .param("state", "state123")
                        .param("scope", "openid unknown")
                        .param("response_type", "code")

        )
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("https://test.redirect.uri/test?" +
                        "error=invalid_scope&error_description=Provided+scopes+not+matches+client+scopes.&state=state123"));

    }

    @Test
    public void whenResponseTypeNotExists_expectRedirectWithError() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://test.redirect.uri/test")
                        .param("state", "state123")
                        .param("scope", "openid")
        )
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("https://test.redirect.uri/test?" +
                        "error=invalid_request&error_description=response_type+parameter+is+missing&state=state123"));

    }

    @Test
    public void whenResponseTypeIsInvalid_expectRedirectWithError() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://test.redirect.uri/test")
                        .param("state", "state123")
                        .param("scope", "openid")
                        .param("response_type", "invalid")

        )
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("https://test.redirect.uri/test?" +
                        "error=unsupported_response_type&error_description=Invalid+response_type+parameter+value.&state=state123"));

    }

    @Test
    public void whenNonceNotExists_expectRedirectWithError() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://test.redirect.uri/test")
                        .param("state", "state123")
                        .param("response_type", "code")
                        .param("scope", "openid")

        )
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("https://test.redirect.uri/test" +
                        "?error=invalid_request&error_description=nonce+parameter+is+missing&state=state123"));

    }

    @Test
    public void whenCodeChallengeNotExists_expectRedirectWithError() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://test.redirect.uri/test")
                        .param("state", "state123")
                        .param("response_type", "code")
                        .param("scope", "openid")
                        .param("nonce", "nonce123")
                        .param("code_challenge_method", "S256")

        )
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("https://test.redirect.uri/test" +
                        "?error=invalid_request&error_description=code_challenge+parameter+is+missing&state=state123"));
    }

    @Test
    public void whenCodeChallengeMethodNotExists_expectRedirectWithError() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://test.redirect.uri/test")
                        .param("state", "state123")
                        .param("response_type", "code")
                        .param("scope", "openid")
                        .param("nonce", "nonce123")
                        .param("code_challenge", "23213213")

        )
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("https://test.redirect.uri/test" +
                        "?error=invalid_request&error_description=code_challenge_method+parameter+is+missing&state=state123"));
    }

    @Test
    public void whenCodeChallengeAndCodeChallengeMethodExistsAndCodeMethodChallengeIsDifferentThanConfigurationValue_expectRedirectWithError() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://test.redirect.uri/test")
                        .param("state", "state123")
                        .param("response_type", "code")
                        .param("scope", "openid")
                        .param("nonce", "nonce123")
                        .param("code_challenge", "23213213")
                        .param("code_challenge_method", "S128")

        )
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("https://test.redirect.uri/test" +
                        "?error=invalid_request&error_description=Provided+code_challenge_method+has+invalid+value.&state=state123"));
    }


    @Test
    public void whenUserNotAuthenticated_expectRedirectToLogin() throws Exception {

        Mockito.when(oAuthUserService.resolveClaims(Mockito.any(HttpServletRequest.class)))
                .thenThrow(new UserNotAuthenticatedException("user not authenticated"));

        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://test.redirect.uri/test")
                        .param("state", "state123")
                        .param("response_type", "code")
                        .param("scope", "openid")
                        .param("nonce", "nonce123")
                        .param("code_challenge", "123123321")
                        .param("code_challenge_method", "S256")
        )
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl("http://login.oauth/login" +
                        "?redirectUri=http://localhost/oauth/auth?client_id=test-client&redirect_uri=https://test.redirect.uri/test&state=state123&response_type=code&scope=openid&nonce=nonce123&code_challenge=123123321&code_challenge_method=S256"));
    }

    @Test
    public void whenUserAuthenticated_expectSuccessRedirectWithAuthorizationCode() throws Exception {

        Mockito.when(oAuthUserService.resolveClaims(Mockito.any(HttpServletRequest.class)))
                .thenReturn(TokenClaims.builder()
                        .idTokenClaims(Map.of("sub", "foo"))
                        .accessTokenClaims(Map.of("sub", "bar"))
                        .build()
                );


        ArgumentCaptor<OAuth2Session> whenSessionCaptor = ArgumentCaptor.forClass(OAuth2Session.class);
        Mockito.when(oAuthSessionService.save(whenSessionCaptor.capture())).thenReturn(new OAuth2Session());


        mockMvc.perform(
                MockMvcRequestBuilders.get("/oauth/auth")
                        .param("client_id", "test-client")
                        .param("redirect_uri", "https://test.redirect.uri/test")
                        .param("state", "state123")
                        .param("response_type", "code")
                        .param("scope", "openid test")
                        .param("nonce", "nonce123")
                        .param("code_challenge", "123123321")
                        .param("code_challenge_method", "S256")
        )
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrl(String.format("https://test.redirect.uri/test?code=%s&state=state123", whenSessionCaptor.getValue().getAuthorizationCode())));


        ArgumentCaptor<OAuth2Session> verifySessionCaptor = ArgumentCaptor.forClass(OAuth2Session.class);
        Mockito.verify(oAuthSessionService).save(verifySessionCaptor.capture());

        OAuth2Session session = verifySessionCaptor.getValue();


        Assertions.assertThat(session.getClientId()).isEqualTo("test-client");
        Assertions.assertThat(session.getRedirectUri()).isEqualTo("https://test.redirect.uri/test");
        Assertions.assertThat(session.getState()).isEqualTo("state123");
        Assertions.assertThat(session.getResponseType()).isEqualTo("code");
        Assertions.assertThat(session.getScope()).isEqualTo("openid test");
        Assertions.assertThat(session.getNonce()).isEqualTo("nonce123");
        Assertions.assertThat(session.getCodeChallenge()).isEqualTo("123123321");
        Assertions.assertThat(session.getCodeChallengeMethod()).isEqualTo("S256");
        Assertions.assertThat(session.getAuthorizationCode()).isEqualTo(whenSessionCaptor.getValue().getAuthorizationCode());
        Assertions.assertThat(session.getAccessTokenPlain()).isNotBlank();
        Assertions.assertThat(session.getIdTokenPlain()).isNotBlank();
        Assertions.assertThat(session.getRefreshToken()).isNotBlank();

        Assertions.assertThat(session.getAuthorizationCode()).isEqualTo(whenSessionCaptor.getValue().getAuthorizationCode());

        PlainJWT idToken = PlainJWT.parse(session.getIdTokenPlain());

        JWTClaimsSet idTokenClaims = idToken.getJWTClaimsSet();
        Assertions.assertThat(idTokenClaims.getSubject()).isEqualTo("foo");
        Assertions.assertThat(idTokenClaims.getIssuer()).isEqualTo("http://test.oauth/oauth");
        Assertions.assertThat(idTokenClaims.getAudience()).containsExactly("test-client");
        Assertions.assertThat(idTokenClaims.getStringClaim("azp")).isEqualTo("test-client");
        Assertions.assertThat(idTokenClaims.getStringClaim("nonce")).isEqualTo("nonce123");


    }

}