package com.celements.spring.security;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.xwiki.context.Execution;
import org.xwiki.model.reference.WikiReference;

import com.celements.auth.MainAdminConfig;
import com.celements.auth.user.User;
import com.celements.auth.user.UserService;
import com.celements.common.test.AbstractComponentTest;
import com.celements.execution.XWikiExecutionProp;
import com.celements.spring.security.oauth2.IdentityService;
import com.celements.spring.security.oauth2.cookietoken.CookieTokenService;
import com.celements.spring.security.oauth2.cookietoken.CookieTokenService.RefreshedTokens;
import com.celements.spring.security.oauth2.filter.ExecutionContextAuthenticationFilter;
import com.celements.spring.security.oauth2.filter.TokenRefreshFilter;
import com.celements.spring.security.oauth2.wiki.TenantOicdActiveRequestMatcher;
import com.xpn.xwiki.user.api.XWikiUser;

public class CelSecurityFilterChainConfigTest extends AbstractComponentTest {

  private CelSecurityFilterChainConfig config;
  private HttpSecurity http;
  private MockHttpServletRequest request;
  private MockHttpServletResponse response;
  private OAuth2AuthorizedClientService clientServiceMock;

  @Before
  public void prepareTest() throws Exception {
    registerComponentMocks(IdentityService.class, CookieTokenService.class,
        UserService.class, MainAdminConfig.class, LogoutHandler.class, LogoutSuccessHandler.class,
        TenantOicdActiveRequestMatcher.class);
    // Create explicitly: component scanning excludes this configuration under the test profile.
    config = getBeanFactory().createBean(CelSecurityFilterChainConfig.class);
    ObjectPostProcessor<Object> postProcessor = new ObjectPostProcessor<>() {
      @Override
      public <O> O postProcess(O object) {
        return object;
      }
    };
    http = new HttpSecurity(postProcessor, new AuthenticationManagerBuilder(postProcessor),
        Map.of(ApplicationContext.class, new StaticApplicationContext()));
    http.authenticationManager(authentication -> authentication);
    http.requestCache(cache -> {});
    http.setSharedObject(ClientRegistrationRepository.class,
        createDefaultMock(ClientRegistrationRepository.class));
    clientServiceMock = createDefaultMock(OAuth2AuthorizedClientService.class);
    http.setSharedObject(OAuth2AuthorizedClientRepository.class,
        new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(clientServiceMock));
    request = new MockHttpServletRequest("GET", "/api/test");
    request.setServletPath("/api/test");
    response = new MockHttpServletResponse();
    SecurityContextHolder.clearContext();
  }

  @After
  public void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  public void test_apiFilterChain_authenticationFilterOrder() throws Exception {
    IdentityService identityServiceMock = getMock(IdentityService.class);
    expect(identityServiceMock.getHost()).andStubReturn("identity.example");
    expect(identityServiceMock.getRealm()).andStubReturn("wiki");
    replayDefault();
    assertAuthenticationFilterOrder(config.apiFilterChain(http));
    verifyDefault();
  }

  @Test
  public void test_loginFilterChain_authenticationFilterOrder() throws Exception {
    IdentityService identityServiceMock = getMock(IdentityService.class);
    expect(identityServiceMock.getHost()).andStubReturn("identity.example");
    expect(identityServiceMock.getRealm()).andStubReturn("wiki");
    expect(identityServiceMock.getLoginUrl()).andStubReturn("/oauth2/authorization/wiki");
    replayDefault();
    assertAuthenticationFilterOrder(createLoginFilterChain());
    verifyDefault();
  }

  @Test
  public void test_apiFilterChain_refreshRejectionReturns401WithoutSession() throws Exception {
    request.setCookies(new Cookie(CookieTokenService.COOKIE_REFRESH_TOKEN, "old-refresh:1000"));
    IdentityService identityServiceMock = getMock(IdentityService.class);
    CookieTokenService tokenServiceMock = getMock(CookieTokenService.class);
    expect(identityServiceMock.getHost()).andStubReturn("identity.example");
    expect(identityServiceMock.getRealm()).andStubReturn("wiki");
    expect(tokenServiceMock.refreshTokens(request)).andThrow(
        new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT)));
    FilterChain downstreamChain = createMock(FilterChain.class);
    replayDefault(downstreamChain);
    SecurityFilterChain chain = config.apiFilterChain(http);
    TokenRefreshFilter refresh = chain.getFilters().stream()
        .filter(TokenRefreshFilter.class::isInstance).map(TokenRefreshFilter.class::cast)
        .findFirst().orElseThrow();
    refresh.doFilter(request, response, downstreamChain);
    assertEquals(401, response.getStatus());
    assertEquals("Bearer", response.getHeader("WWW-Authenticate"));
    assertNull(response.getRedirectedUrl());
    assertNull(request.getSession(false));
    verifyDefault(downstreamChain);
  }

  @Test
  public void test_loginFilterChain_refreshRejectionSavesRequestAndRedirectsToLogin()
      throws Exception {
    request.setContextPath("/wiki");
    request.setRequestURI("/wiki/target");
    request.setServletPath("/target");
    request.setCookies(new Cookie(CookieTokenService.COOKIE_REFRESH_TOKEN, "old-refresh:1000"));
    IdentityService identityServiceMock = getMock(IdentityService.class);
    CookieTokenService tokenServiceMock = getMock(CookieTokenService.class);
    expect(identityServiceMock.getHost()).andStubReturn("identity.example");
    expect(identityServiceMock.getRealm()).andStubReturn("wiki");
    expect(identityServiceMock.getLoginUrl()).andStubReturn("/oauth2/authorization/wiki");
    expect(tokenServiceMock.refreshTokens(request)).andThrow(
        new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT)));
    FilterChain downstreamChain = createMock(FilterChain.class);
    replayDefault(downstreamChain);
    SecurityFilterChain chain = createLoginFilterChain();
    TokenRefreshFilter refresh = chain.getFilters().stream()
        .filter(TokenRefreshFilter.class::isInstance).map(TokenRefreshFilter.class::cast)
        .findFirst().orElseThrow();
    refresh.doFilter(request, response, downstreamChain);
    assertEquals(302, response.getStatus());
    assertEquals("/wiki/oauth2/authorization/wiki", response.getRedirectedUrl());
    assertEquals("http://localhost/wiki/target", new HttpSessionRequestCache()
        .getRequest(request, response).getRedirectUrl());
    verifyDefault(downstreamChain);
  }

  @Test
  public void test_apiFilterChain_refreshCookieOnlyAuthenticatesOriginalRequest() throws Exception {
    request.setCookies(new Cookie(CookieTokenService.COOKIE_REFRESH_TOKEN, "old-refresh:1000"));
    IdentityService identityServiceMock = getMock(IdentityService.class);
    CookieTokenService tokenServiceMock = getMock(CookieTokenService.class);
    RefreshedTokens refreshedTokens = createRefreshedTokens();
    Jwt jwt = createAccessJwt();
    User userMock = createMock(User.class);
    var xwikiUser = new XWikiUser("XWiki.TestUser", false);
    FilterChain downstreamChain = createMock(FilterChain.class);
    expect(identityServiceMock.getHost()).andStubReturn("identity.example");
    expect(identityServiceMock.getRealm()).andStubReturn("wiki");
    expect(tokenServiceMock.refreshTokens(isA(HttpServletRequest.class)))
        .andReturn(Optional.of(refreshedTokens));
    tokenServiceMock.storeTokens(isA(HttpServletResponse.class), same(refreshedTokens.accessToken()),
        same(refreshedTokens.refreshToken()));
    // Authentication must depend on the actual credential handoff, not a fixed mock token.
    expect(tokenServiceMock.getAccessToken(isA(HttpServletRequest.class))).andAnswer(() -> {
      var currentRequest = (HttpServletRequest) getCurrentArguments()[0];
      return Optional.ofNullable((String) currentRequest
          .getAttribute(CookieTokenService.REFRESHED_ACCESS_TOKEN_ATTRIBUTE));
    });
    expect(identityServiceMock.getAuthenticationManagerForWiki(isA(WikiReference.class)))
        .andReturn(authentication -> {
          assertEquals("renewed-access", ((BearerTokenAuthenticationToken) authentication).getToken());
          return new JwtAuthenticationToken(jwt, List.of());
        });
    expect(getMock(MainAdminConfig.class).isAutoLoginEnabled()).andReturn(false);
    expect(getMock(UserService.class).getPossibleUserForLoginField("user", Set.of("email")))
        .andReturn(Optional.of(userMock));
    expect(userMock.isGlobal()).andStubReturn(false);
    expect(userMock.asXWikiUser()).andStubReturn(xwikiUser);
    expect(userMock.email()).andStubReturn(Optional.of("user@example.org"));
    downstreamChain.doFilter(isA(HttpServletRequest.class), isA(HttpServletResponse.class));
    expectLastCall().andAnswer(() -> {
      var authentication = SecurityContextHolder.getContext().getAuthentication();
      assertNotNull(authentication);
      assertTrue(authentication.isAuthenticated());
      assertEquals("user-id", authentication.getName());
      assertSame(xwikiUser, getBeanFactory().getBean(Execution.class).getContext()
          .get(XWikiExecutionProp.XWIKI_USER).orElseThrow());
      ((HttpServletResponse) getCurrentArguments()[1]).setStatus(204);
      return null;
    });
    replayDefault(userMock, downstreamChain);
    new FilterChainProxy(config.apiFilterChain(http)).doFilter(request, response, downstreamChain);
    assertRequestCompletedWithoutRedirect();
    assertNull(request.getSession(false));
    verifyDefault(userMock, downstreamChain);
  }

  @Test
  public void test_loginFilterChain_refreshCookieOnlyAuthenticatesOriginalRequest() throws Exception {
    request.setContextPath("/wiki");
    request.setRequestURI("/wiki/target");
    request.setServletPath("/target");
    request.setCookies(new Cookie(CookieTokenService.COOKIE_REFRESH_TOKEN, "old-refresh:1000"));
    IdentityService identityServiceMock = getMock(IdentityService.class);
    CookieTokenService tokenServiceMock = getMock(CookieTokenService.class);
    RefreshedTokens refreshedTokens = createRefreshedTokens();
    Jwt jwt = createAccessJwt();
    User userMock = createMock(User.class);
    var xwikiUser = new XWikiUser("XWiki.TestUser", false);
    FilterChain downstreamChain = createMock(FilterChain.class);
    expect(identityServiceMock.getHost()).andStubReturn("identity.example");
    expect(identityServiceMock.getRealm()).andStubReturn("wiki");
    expect(identityServiceMock.getLoginUrl()).andStubReturn("/oauth2/authorization/wiki");
    expect(getMock(TenantOicdActiveRequestMatcher.class).matches(isA(HttpServletRequest.class)))
        .andReturn(true);
    expect(tokenServiceMock.refreshTokens(isA(HttpServletRequest.class)))
        .andReturn(Optional.of(refreshedTokens));
    tokenServiceMock.storeTokens(isA(HttpServletResponse.class), same(refreshedTokens.accessToken()),
        same(refreshedTokens.refreshToken()));
    // Authentication must depend on the actual credential handoff, not a fixed mock token.
    expect(tokenServiceMock.getAccessToken(isA(HttpServletRequest.class))).andAnswer(() -> {
      var currentRequest = (HttpServletRequest) getCurrentArguments()[0];
      return Optional.ofNullable((String) currentRequest
          .getAttribute(CookieTokenService.REFRESHED_ACCESS_TOKEN_ATTRIBUTE));
    });
    expect(identityServiceMock.getAuthenticationManagerForWiki(isA(WikiReference.class)))
        .andReturn(authentication -> {
          assertEquals("renewed-access", ((BearerTokenAuthenticationToken) authentication).getToken());
          return new JwtAuthenticationToken(jwt, List.of());
        });
    expect(getMock(MainAdminConfig.class).isAutoLoginEnabled()).andReturn(false);
    expect(getMock(UserService.class).getPossibleUserForLoginField("user", Set.of("email")))
        .andReturn(Optional.of(userMock));
    expect(userMock.isGlobal()).andStubReturn(false);
    expect(userMock.asXWikiUser()).andStubReturn(xwikiUser);
    expect(userMock.email()).andStubReturn(Optional.of("user@example.org"));
    downstreamChain.doFilter(isA(HttpServletRequest.class), isA(HttpServletResponse.class));
    expectLastCall().andAnswer(() -> {
      var authentication = SecurityContextHolder.getContext().getAuthentication();
      assertNotNull(authentication);
      assertTrue(authentication.isAuthenticated());
      assertEquals("user-id", authentication.getName());
      assertSame(xwikiUser, getBeanFactory().getBean(Execution.class).getContext()
          .get(XWikiExecutionProp.XWIKI_USER).orElseThrow());
      ((HttpServletResponse) getCurrentArguments()[1]).setStatus(204);
      return null;
    });
    replayDefault(userMock, downstreamChain);
    new FilterChainProxy(createLoginFilterChain()).doFilter(request, response, downstreamChain);
    assertRequestCompletedWithoutRedirect();
    verifyDefault(userMock, downstreamChain);
  }

  private RefreshedTokens createRefreshedTokens() {
    Instant now = Instant.now();
    return new RefreshedTokens(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        "renewed-access", now, now.plusSeconds(300)), new OAuth2RefreshToken("renewed-refresh", now));
  }

  private Jwt createAccessJwt() {
    Instant now = Instant.now();
    return Jwt.withTokenValue("renewed-access").header("alg", "RS256")
        .issuedAt(now).expiresAt(now.plusSeconds(300)).subject("user-id")
        .claim("preferred_username", "user").claim("email", "user@example.org").build();
  }

  private void assertRequestCompletedWithoutRedirect() {
    assertEquals(204, response.getStatus());
    assertEquals(1, request.getCookies().length);
    assertEquals(CookieTokenService.COOKIE_REFRESH_TOKEN, request.getCookies()[0].getName());
    assertEquals("old-refresh:1000", request.getCookies()[0].getValue());
    assertNull(response.getRedirectedUrl());
  }

  private SecurityFilterChain createLoginFilterChain() throws Exception {
    return config.loginFilterChain(http, getMock(LogoutHandler.class),
        getMock(LogoutSuccessHandler.class), clientServiceMock,
        getMock(TenantOicdActiveRequestMatcher.class));
  }

  private void assertAuthenticationFilterOrder(SecurityFilterChain chain) {
    var filterTypes = chain.getFilters().stream().map(Object::getClass).toList();
    assertEquals(1, Collections.frequency(filterTypes, TokenRefreshFilter.class));
    assertEquals(1, Collections.frequency(filterTypes, BearerTokenAuthenticationFilter.class));
    assertEquals(1, Collections.frequency(filterTypes, ExecutionContextAuthenticationFilter.class));
    int refresh = filterTypes.indexOf(TokenRefreshFilter.class);
    int bearer = filterTypes.indexOf(BearerTokenAuthenticationFilter.class);
    assertTrue("Refresh must precede bearer authentication", refresh < bearer);
    assertTrue("User mapping must follow bearer authentication",
        bearer < filterTypes.indexOf(ExecutionContextAuthenticationFilter.class));
  }
}
