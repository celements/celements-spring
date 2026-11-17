package com.celements.spring.security.oauth2.wiki;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import com.celements.common.test.AbstractComponentTest;
import com.celements.spring.security.oauth2.cookietoken.CookieTokenService;

public class CelAuthenticationSuccessHandlerTest extends AbstractComponentTest {

  private CelAuthenticationSuccessHandler handler;

  @Before
  public void prepareTest() throws Exception {
    registerComponentMocks(CookieTokenService.class, OAuth2AuthorizedClientService.class);
    handler = new CelAuthenticationSuccessHandler(getMock(OAuth2AuthorizedClientService.class),
        getMock(CookieTokenService.class));
  }

  @Test
  public void test_onAuthenticationSuccess_storesAuthorizedClientTokens() throws Exception {
    Instant now = Instant.now();
    var access = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        "login-access", now, now.plusSeconds(300));
    var refresh = new OAuth2RefreshToken("login-refresh", now);
    OAuth2AuthorizedClient clientMock = createMock(OAuth2AuthorizedClient.class);
    var principal = new DefaultOAuth2User(List.of(), Map.of("sub", "user"), "sub");
    var authentication = new OAuth2AuthenticationToken(principal, List.of(), "wiki");
    expect(getMock(OAuth2AuthorizedClientService.class).loadAuthorizedClient("wiki", "user"))
        .andReturn(clientMock);
    expect(clientMock.getAccessToken()).andReturn(access);
    expect(clientMock.getRefreshToken()).andReturn(refresh);
    var request = new MockHttpServletRequest();
    var response = new MockHttpServletResponse();
    getMock(CookieTokenService.class).storeTokens(same(response), same(access), same(refresh));
    replayDefault(clientMock);
    handler.onAuthenticationSuccess(request, response, authentication);
    verifyDefault(clientMock);
  }

  @Test
  public void test_onAuthenticationSuccess_noSavedRequestRedirectsToRoot() throws Exception {
    var request = new MockHttpServletRequest();
    var response = new MockHttpServletResponse();
    replayDefault();
    handler.onAuthenticationSuccess(request, response,
        new UsernamePasswordAuthenticationToken("user", "unused"));
    assertEquals("/", response.getRedirectedUrl());
    verifyDefault();
  }

  @Test
  public void test_onAuthenticationSuccess_savedRequestRedirectsToOriginalDestination()
      throws Exception {
    var target = new MockHttpServletRequest("GET", "/wiki/target");
    target.setContextPath("/wiki");
    target.setServletPath("/target");
    var response = new MockHttpServletResponse();
    new HttpSessionRequestCache().saveRequest(target, response);
    var callback = new MockHttpServletRequest("GET", "/wiki/login/oauth2/code/wiki");
    callback.setContextPath("/wiki");
    callback.setServletPath("/login/oauth2/code/wiki");
    callback.setSession(target.getSession(false));
    replayDefault();
    handler.onAuthenticationSuccess(callback, response,
        new UsernamePasswordAuthenticationToken("user", "unused"));
    assertEquals("http://localhost/wiki/target", response.getRedirectedUrl());
    verifyDefault();
  }
}
