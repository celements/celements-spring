package com.celements.spring.security.oauth2.cookietoken;

import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import javax.servlet.http.Cookie;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import com.celements.common.test.AbstractComponentTest;
import com.celements.spring.security.oauth2.IdentityService;
import com.celements.spring.security.oauth2.auth.WikiClientRegistrationRepository;

public class CookieTokenServiceTest extends AbstractComponentTest {

  private static final Instant REFRESH_ISSUED_AT = Instant.parse("2026-01-01T00:00:00Z");

  private CookieTokenService tokenService;
  private JwtDecoder decoderMock;
  private MockHttpServletRequest request;
  private MockRestServiceServer server;

  @Before
  public void prepareTest() throws Exception {
    registerComponentMocks(IdentityService.class, WikiClientRegistrationRepository.class);
    tokenService = getBeanFactory().getBean(CookieTokenService.class);
    decoderMock = createDefaultMock(JwtDecoder.class);
    request = new MockHttpServletRequest();
    var restTemplate = new RestTemplate(List.of(new FormHttpMessageConverter(),
        new OAuth2AccessTokenResponseHttpMessageConverter()));
    restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
    server = MockRestServiceServer.createServer(restTemplate);
    ((DefaultRefreshTokenTokenResponseClient) ReflectionTestUtils
        .getField(tokenService, "refreshClient")).setRestOperations(restTemplate);
    SecurityContextHolder.clearContext();
  }

  @After
  public void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  public void test_refreshTokens_refreshCookieOnlyNeedsNoAuthentication() {
    request.setCookies(createRefreshCookie());
    expectRefreshExchange("new-refresh");
    replayDefault();
    assertNull(SecurityContextHolder.getContext().getAuthentication());
    var result = tokenService.refreshTokens(request).orElseThrow();
    assertEquals("new-access", result.accessToken().getTokenValue());
    assertEquals(Set.of(), result.accessToken().getScopes());
    assertEquals("new-refresh", result.refreshToken().getTokenValue());
    assertTrue(result.refreshToken().getIssuedAt().isAfter(REFRESH_ISSUED_AT));
    assertNull(SecurityContextHolder.getContext().getAuthentication());
    server.verify();
    verifyDefault();
  }

  @Test
  public void test_refreshTokens_expiredAccessTokenIsRefreshed() {
    request.setCookies(createRefreshCookie(),
        new Cookie(CookieTokenService.COOKIE_ACCESS_TOKEN, "old-access"));
    expect(getMock(IdentityService.class).getJwtDecoder()).andReturn(decoderMock);
    expect(decoderMock.decode("old-access")).andThrow(new JwtException("Token expired"));
    expectRefreshExchange("new-refresh");
    replayDefault();
    assertEquals("new-access", tokenService.refreshTokens(request).orElseThrow()
        .accessToken().getTokenValue());
    server.verify();
    verifyDefault();
  }

  @Test
  public void test_refreshTokens_invalidAccessTokenIsRefreshed() {
    request.setCookies(createRefreshCookie(),
        new Cookie(CookieTokenService.COOKIE_ACCESS_TOKEN, "old-access"));
    expect(getMock(IdentityService.class).getJwtDecoder()).andReturn(decoderMock);
    expect(decoderMock.decode("old-access")).andThrow(new JwtException("Signature rejected"));
    expectRefreshExchange("new-refresh");
    replayDefault();
    assertEquals("new-access", tokenService.refreshTokens(request).orElseThrow()
        .accessToken().getTokenValue());
    server.verify();
    verifyDefault();
  }

  @Test
  public void test_refreshTokens_healthyAccessTokenSkipsExchange() {
    request.setCookies(createRefreshCookie(),
        new Cookie(CookieTokenService.COOKIE_ACCESS_TOKEN, "old-access"));
    expect(getMock(IdentityService.class).getJwtDecoder()).andReturn(decoderMock);
    expect(decoderMock.decode("old-access")).andReturn(createAccessJwt(600));
    replayDefault();
    assertTrue(tokenService.refreshTokens(request).isEmpty());
    server.verify();
    verifyDefault();
  }

  @Test
  public void test_refreshTokens_healthyAccessTokenIgnoresMalformedRefreshCookie() {
    request.setCookies(new Cookie(CookieTokenService.COOKIE_REFRESH_TOKEN, ":0"),
        new Cookie(CookieTokenService.COOKIE_ACCESS_TOKEN, "old-access"));
    expect(getMock(IdentityService.class).getJwtDecoder()).andReturn(decoderMock);
    expect(decoderMock.decode("old-access")).andReturn(createAccessJwt(600));
    replayDefault();
    assertTrue(tokenService.refreshTokens(request).isEmpty());
    server.verify();
    verifyDefault();
  }

  @Test
  public void test_refreshTokens_accessTokenInsideRefreshWindowIsRefreshed() {
    request.setCookies(createRefreshCookie(),
        new Cookie(CookieTokenService.COOKIE_ACCESS_TOKEN, "old-access"));
    expect(getMock(IdentityService.class).getJwtDecoder()).andReturn(decoderMock);
    expect(decoderMock.decode("old-access")).andReturn(createAccessJwt(60));
    expectRefreshExchange("new-refresh");
    replayDefault();
    var result = tokenService.refreshTokens(request).orElseThrow();
    assertEquals("new-access", result.accessToken().getTokenValue());
    server.verify();
    verifyDefault();
  }

  @Test
  public void test_refreshTokens_missingResponseScopesPreserveExistingScopes() {
    request.setCookies(createRefreshCookie(),
        new Cookie(CookieTokenService.COOKIE_ACCESS_TOKEN, "old-access"));
    expect(getMock(IdentityService.class).getJwtDecoder()).andReturn(decoderMock);
    expect(decoderMock.decode("old-access")).andReturn(createAccessJwt(60));
    expectRefreshExchange("new-refresh");
    replayDefault();
    var result = tokenService.refreshTokens(request).orElseThrow();
    assertEquals(Set.of("openid", "profile"), result.accessToken().getScopes());
    server.verify();
    verifyDefault();
  }

  @Test
  public void test_refreshTokens_noRefreshCookieSkipsExchangeAndDecode() {
    request.setCookies(new Cookie(CookieTokenService.COOKIE_ACCESS_TOKEN, "old-access"));
    replayDefault();
    assertTrue(tokenService.refreshTokens(request).isEmpty());
    server.verify();
    verifyDefault();
  }

  @Test
  public void test_getRefreshToken_malformedValuesReturnEmpty() {
    replayDefault();
    for (String value : new String[] { null, "", " ", ":", ":0", " :0" }) {
      request.setCookies(new Cookie(CookieTokenService.COOKIE_REFRESH_TOKEN, value));
      assertTrue(tokenService.getRefreshToken(request).isEmpty());
    }
    verifyDefault();
  }

  @Test
  public void test_getRefreshToken_missingIssuedAtPreservesToken() {
    request.setCookies(new Cookie(CookieTokenService.COOKIE_REFRESH_TOKEN, "opaque-refresh"));
    replayDefault();
    OAuth2RefreshToken token = tokenService.getRefreshToken(request).orElseThrow();
    assertEquals("opaque-refresh", token.getTokenValue());
    assertNull(token.getIssuedAt());
    verifyDefault();
  }

  @Test
  public void test_getRefreshToken_invalidIssuedAtPreservesToken() {
    replayDefault();
    for (String suffix : List.of("", "invalid", "9223372036854775808")) {
      request.setCookies(new Cookie(CookieTokenService.COOKIE_REFRESH_TOKEN,
          "opaque-refresh:" + suffix));
      OAuth2RefreshToken token = tokenService.getRefreshToken(request).orElseThrow();
      assertEquals("opaque-refresh", token.getTokenValue());
      assertNull(token.getIssuedAt());
    }
    verifyDefault();
  }

  @Test
  public void test_refreshTokens_malformedRefreshCookieProducesInvalidGrant() {
    request.setCookies(new Cookie(CookieTokenService.COOKIE_REFRESH_TOKEN, ":0"));
    replayDefault();
    var failure = assertThrows(OAuth2AuthorizationException.class,
        () -> tokenService.refreshTokens(request));
    assertEquals(OAuth2ErrorCodes.INVALID_GRANT, failure.getError().getErrorCode());
    server.verify();
    verifyDefault();
  }

  @Test
  public void test_refreshTokens_expiredAccessAndMalformedRefreshProduceInvalidGrant() {
    request.setCookies(new Cookie(CookieTokenService.COOKIE_ACCESS_TOKEN, "old-access"),
        new Cookie(CookieTokenService.COOKIE_REFRESH_TOKEN, ":0"));
    expect(getMock(IdentityService.class).getJwtDecoder()).andReturn(decoderMock);
    expect(decoderMock.decode("old-access")).andThrow(new JwtException("Token expired"));
    replayDefault();
    var failure = assertThrows(OAuth2AuthorizationException.class,
        () -> tokenService.refreshTokens(request));
    assertEquals(OAuth2ErrorCodes.INVALID_GRANT, failure.getError().getErrorCode());
    server.verify();
    verifyDefault();
  }

  @Test
  public void test_refreshTokens_responseWithoutRefreshTokenPreservesOriginalMetadata() {
    request.setCookies(createRefreshCookie());
    expectRefreshExchange(null);
    replayDefault();
    var result = tokenService.refreshTokens(request).orElseThrow();
    assertEquals("old-refresh", result.refreshToken().getTokenValue());
    assertEquals(REFRESH_ISSUED_AT, result.refreshToken().getIssuedAt());
    assertNull(result.refreshToken().getExpiresAt());
    server.verify();
    verifyDefault();
  }

  @Test
  public void test_storeTokens_cookieAttributesAndRefreshEncoding() {
    Instant now = Instant.now();
    var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        "access", now, now.plusSeconds(300));
    var refreshToken = new OAuth2RefreshToken("refresh", REFRESH_ISSUED_AT, now.plusSeconds(600));
    var response = new MockHttpServletResponse();
    replayDefault();
    tokenService.storeTokens(response, accessToken, refreshToken);
    assertEquals(2, response.getCookies().length);
    Cookie access = response.getCookie(CookieTokenService.COOKIE_ACCESS_TOKEN);
    assertEquals("access", access.getValue());
    assertCookieAttributes(access, 300);
    Cookie refresh = response.getCookie(CookieTokenService.COOKIE_REFRESH_TOKEN);
    assertEquals("refresh:" + REFRESH_ISSUED_AT.toEpochMilli(), refresh.getValue());
    assertCookieAttributes(refresh, 600);
    verifyDefault();
  }

  @Test
  public void test_storeTokens_tokensWithoutExpiryUseSessionCookies() {
    var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        "access", null, null);
    var response = new MockHttpServletResponse();
    replayDefault();
    tokenService.storeTokens(response, accessToken,
        new OAuth2RefreshToken("refresh", REFRESH_ISSUED_AT));
    assertEquals(-1, response.getCookie(CookieTokenService.COOKIE_ACCESS_TOKEN).getMaxAge());
    assertEquals(-1, response.getCookie(CookieTokenService.COOKIE_REFRESH_TOKEN).getMaxAge());
    verifyDefault();
  }

  @Test
  public void test_storeTokens_refreshTokenWithoutIssuedAtIsStoredUnencoded() {
    Instant now = Instant.now();
    var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        "access", now, now.plusSeconds(300));
    var response = new MockHttpServletResponse();
    replayDefault();
    tokenService.storeTokens(response, accessToken, new OAuth2RefreshToken("refresh", null));
    assertEquals("refresh", response.getCookie(CookieTokenService.COOKIE_REFRESH_TOKEN).getValue());
    verifyDefault();
  }

  @Test
  public void test_storeTokens_noRefreshTokenStoresOnlyAccessCookie() {
    var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        "access", null, null);
    var response = new MockHttpServletResponse();
    replayDefault();
    tokenService.storeTokens(response, accessToken, null);
    assertEquals(1, response.getCookies().length);
    assertEquals("access", response.getCookie(CookieTokenService.COOKIE_ACCESS_TOKEN).getValue());
    assertNull(response.getCookie(CookieTokenService.COOKIE_REFRESH_TOKEN));
    verifyDefault();
  }

  @Test
  public void test_getAccessToken_requestAttributeTakesPrecedenceWithoutCookieDecoding() {
    request.setCookies(new Cookie(CookieTokenService.COOKIE_ACCESS_TOKEN, "invalid-access"));
    request.setAttribute(CookieTokenService.REFRESHED_ACCESS_TOKEN_ATTRIBUTE, "new-access");
    replayDefault();
    assertEquals("new-access", tokenService.getAccessToken(request).orElseThrow());
    verifyDefault();
  }

  @Test
  public void test_getAccessToken_noAttributeFallsBackToCookie() {
    request.setCookies(new Cookie(CookieTokenService.COOKIE_ACCESS_TOKEN, "old-access"));
    expect(getMock(IdentityService.class).getJwtDecoder()).andReturn(decoderMock);
    expect(decoderMock.decode("old-access")).andReturn(createAccessJwt(600));
    replayDefault();
    assertEquals("old-access", tokenService.getAccessToken(request).orElseThrow());
    verifyDefault();
  }

  @Test
  public void test_getAccessTokenFromCookie_validCookieReturnsAccessToken() {
    request.setCookies(new Cookie(CookieTokenService.COOKIE_ACCESS_TOKEN, "old-access"));
    Jwt jwt = createAccessJwt(600);
    expect(getMock(IdentityService.class).getJwtDecoder()).andReturn(decoderMock);
    expect(decoderMock.decode("old-access")).andReturn(jwt);
    replayDefault();
    OAuth2AccessToken token = tokenService.getAccessTokenFromCookie(request).orElseThrow();
    assertEquals("old-access", token.getTokenValue());
    assertEquals(OAuth2AccessToken.TokenType.BEARER, token.getTokenType());
    assertEquals(jwt.getIssuedAt(), token.getIssuedAt());
    assertEquals(jwt.getExpiresAt(), token.getExpiresAt());
    assertEquals(Set.of("openid", "profile"), token.getScopes());
    verifyDefault();
  }

  @Test
  public void test_getAccessToken_noCookieOrAttributeReturnsEmpty() {
    replayDefault();
    assertTrue(tokenService.getAccessToken(request).isEmpty());
    verifyDefault();
  }

  private Cookie createRefreshCookie() {
    return new Cookie(CookieTokenService.COOKIE_REFRESH_TOKEN,
        "old-refresh:" + REFRESH_ISSUED_AT.toEpochMilli());
  }

  private Jwt createAccessJwt(long expiresIn) {
    Instant now = Instant.now();
    return Jwt.withTokenValue("old-access").header("alg", "RS256")
        .issuedAt(now.minusSeconds(300)).expiresAt(now.plusSeconds(expiresIn))
        .claim("scope", List.of("openid", "profile")).build();
  }

  private void expectRefreshExchange(String refreshValue) {
    ClientRegistration registration = ClientRegistration.withRegistrationId("current-wiki")
        .clientId("wiki-client").clientSecret("wiki-secret")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://wiki.example/login/oauth2/code/current-wiki")
        .authorizationUri("https://identity.example/auth")
        .tokenUri("https://identity.example/token").build();
    expect(getMock(IdentityService.class).getRegistrationId()).andReturn("current-wiki");
    expect(getMock(WikiClientRegistrationRepository.class).findByRegistrationId("current-wiki"))
        .andReturn(registration);
    String refreshJson = (refreshValue == null) ? "" : ",\"refresh_token\":\"" + refreshValue + "\"";
    server.expect(requestTo("https://identity.example/token"))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header("Authorization", "Basic d2lraS1jbGllbnQ6d2lraS1zZWNyZXQ="))
        .andExpect(content().string("grant_type=refresh_token&refresh_token=old-refresh"))
        .andRespond(withSuccess("{\"access_token\":\"new-access\",\"token_type\":\"Bearer\","
            + "\"expires_in\":300" + refreshJson + "}", MediaType.APPLICATION_JSON));
  }

  private void assertCookieAttributes(Cookie cookie, int maxAge) {
    assertTrue(cookie.isHttpOnly());
    assertTrue(cookie.getSecure());
    assertEquals("/", cookie.getPath());
    assertNull(cookie.getDomain());
    assertTrue("Cookie lifetime must preserve token expiry", cookie.getMaxAge() <= maxAge
        && cookie.getMaxAge() >= maxAge - 5);
  }
}
