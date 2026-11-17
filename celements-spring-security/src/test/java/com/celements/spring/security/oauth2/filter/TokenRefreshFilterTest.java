package com.celements.spring.security.oauth2.filter;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.time.Instant;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletResponse;

import org.easymock.Capture;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.celements.common.test.AbstractComponentTest;
import com.celements.spring.security.oauth2.cookietoken.CookieTokenService;
import com.celements.spring.security.oauth2.cookietoken.CookieTokenService.RefreshedTokens;

public class TokenRefreshFilterTest extends AbstractComponentTest {

  private CookieTokenService tokenServiceMock;
  private AuthenticationEntryPoint entryPointMock;
  private FilterChain downstreamChain;
  private TokenRefreshFilter filter;
  private MockHttpServletRequest request;
  private MockHttpServletResponse response;
  private RefreshedTokens refreshedTokens;

  @Before
  public void prepareTest() throws Exception {
    tokenServiceMock = createDefaultMock(CookieTokenService.class);
    entryPointMock = createDefaultMock(AuthenticationEntryPoint.class);
    downstreamChain = createDefaultMock(FilterChain.class);
    filter = new TokenRefreshFilter(tokenServiceMock, entryPointMock);
    request = new MockHttpServletRequest("GET", "/resource");
    response = new MockHttpServletResponse();
    Instant now = Instant.now();
    refreshedTokens = new RefreshedTokens(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        "renewed-access", now, now.plusSeconds(300)),
        new OAuth2RefreshToken("renewed-refresh", now));
  }

  @Test
  public void test_shouldNotFilter_bearerHeader() {
    request.addHeader("Authorization", "Bearer explicit-access");
    replayDefault();
    assertTrue(filter.shouldNotFilter(request));
    verifyDefault();
  }

  @Test
  public void test_shouldNotFilter_malformedBearerHeader() {
    request.addHeader("Authorization", "Bearer not a token");
    replayDefault();
    assertTrue(filter.shouldNotFilter(request));
    verifyDefault();
  }

  @Test
  public void test_shouldNotFilter_basicHeader() {
    request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
    replayDefault();
    assertFalse(filter.shouldNotFilter(request));
    verifyDefault();
  }

  @Test
  public void test_shouldNotFilter_noAuthorizationHeader() {
    replayDefault();
    assertFalse(filter.shouldNotFilter(request));
    verifyDefault();
  }

  @Test
  public void test_doFilterInternal_successfulRefreshStoresTokensAndExposesAccessToken()
      throws Exception {
    expect(tokenServiceMock.refreshTokens(request)).andReturn(Optional.of(refreshedTokens));
    Capture<HttpServletResponse> storedResponse = newCapture();
    tokenServiceMock.storeTokens(capture(storedResponse), same(refreshedTokens.accessToken()),
        same(refreshedTokens.refreshToken()));
    downstreamChain.doFilter(same(request), same(response));
    expectLastCall().andAnswer(() -> {
      assertTrue("Tokens must be stored before continuing the chain", storedResponse.hasCaptured());
      assertSame(response, storedResponse.getValue());
      assertEquals("renewed-access",
          request.getAttribute(CookieTokenService.REFRESHED_ACCESS_TOKEN_ATTRIBUTE));
      return null;
    });
    replayDefault();
    filter.doFilterInternal(request, response, downstreamChain);
    verifyDefault();
  }

  @Test
  public void test_doFilterInternal_noRefreshResultContinuesWithoutTokenChanges() throws Exception {
    expect(tokenServiceMock.refreshTokens(request)).andReturn(Optional.empty());
    downstreamChain.doFilter(same(request), same(response));
    replayDefault();
    filter.doFilterInternal(request, response, downstreamChain);
    assertNull(request.getAttribute(CookieTokenService.REFRESHED_ACCESS_TOKEN_ATTRIBUTE));
    verifyDefault();
  }

  @Test
  public void test_doFilterInternal_invalidGrantInvokesEntryPointAndStopsChain() throws Exception {
    expect(tokenServiceMock.refreshTokens(request)).andThrow(
        new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT)));
    entryPointMock.commence(same(request), same(response), isA(AuthenticationException.class));
    replayDefault();
    filter.doFilterInternal(request, response, downstreamChain);
    assertNull(request.getAttribute(CookieTokenService.REFRESHED_ACCESS_TOKEN_ATTRIBUTE));
    verifyDefault();
  }

  @Test
  public void test_doFilterInternal_refreshServerErrorPropagates() throws Exception {
    var failure = new OAuth2AuthorizationException(new OAuth2Error("server_error"));
    expect(tokenServiceMock.refreshTokens(request)).andThrow(failure);
    replayDefault();
    assertSame(failure, assertThrows(OAuth2AuthorizationException.class,
        () -> filter.doFilterInternal(request, response, downstreamChain)));
    assertNull(request.getAttribute(CookieTokenService.REFRESHED_ACCESS_TOKEN_ATTRIBUTE));
    verifyDefault();
  }

  @Test
  public void test_doFilterInternal_downstreamInvalidGrantPropagates() throws Exception {
    expect(tokenServiceMock.refreshTokens(request)).andReturn(Optional.of(refreshedTokens));
    tokenServiceMock.storeTokens(response, refreshedTokens.accessToken(),
        refreshedTokens.refreshToken());
    var failure = new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
    downstreamChain.doFilter(request, response);
    expectLastCall().andThrow(failure);
    replayDefault();
    assertSame(failure, assertThrows(OAuth2AuthorizationException.class,
        () -> filter.doFilterInternal(request, response, downstreamChain)));
    verifyDefault();
  }
}
