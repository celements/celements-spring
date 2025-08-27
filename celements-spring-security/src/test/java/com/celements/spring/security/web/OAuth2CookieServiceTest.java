package com.celements.spring.security.web;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import com.celements.common.test.AbstractComponentTest;
import com.celements.spring.security.api.IdentityService;

public class OAuth2CookieServiceTest extends AbstractComponentTest {

  private OAuth2CookieService oauth2CookieService;

  @Before
  public void prepare() throws Exception {
    registerComponentMock(IdentityService.class);
    oauth2CookieService = getSpringContext().getBean(OAuth2CookieService.class);
  }

  @Test
  public void test_hasAccessTokenChanged_bothAccessToken_empty() {
    OAuth2AuthorizedClient clientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    expect(clientMock.getAccessToken()).andReturn(null).atLeastOnce();
    OAuth2AuthorizedClient oldClientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    expect(oldClientMock.getAccessToken()).andReturn(null).atLeastOnce();
    Optional<OAuth2AuthorizedClient> oldClientMockOpt = Optional.of(oldClientMock);
    replayDefault();
    assertFalse(oauth2CookieService.hasAccessTokenChanged(oldClientMockOpt, clientMock));
    verifyDefault();
  }

  @Test
  public void test_hasAccessTokenChanged_bothAccessValue_empty() {
    OAuth2AuthorizedClient clientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2AccessToken accessTokenMock = createDefaultMock(OAuth2AccessToken.class);
    expect(clientMock.getAccessToken()).andReturn(accessTokenMock).atLeastOnce();
    expect(accessTokenMock.getTokenValue()).andReturn(null).atLeastOnce();
    OAuth2AuthorizedClient oldClientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    expect(oldClientMock.getAccessToken()).andReturn(null).atLeastOnce();
    Optional<OAuth2AuthorizedClient> oldClientMockOpt = Optional.of(oldClientMock);
    replayDefault();
    assertFalse(oauth2CookieService.hasAccessTokenChanged(oldClientMockOpt, clientMock));
    verifyDefault();
  }

  @Test
  public void test_hasAccessTokenChanged_expire_newToken_empty() {
    OAuth2AuthorizedClient clientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2AccessToken accessTokenMock = createDefaultMock(OAuth2AccessToken.class);
    expect(clientMock.getAccessToken()).andReturn(accessTokenMock).atLeastOnce();
    expect(accessTokenMock.getTokenValue()).andReturn(null).atLeastOnce();
    OAuth2AuthorizedClient oldClientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2AccessToken oldAccessTokenMock = createDefaultMock(OAuth2AccessToken.class);
    expect(oldClientMock.getAccessToken()).andReturn(oldAccessTokenMock).atLeastOnce();
    expect(oldAccessTokenMock.getTokenValue()).andReturn("newJwtToken").atLeastOnce();
    Optional<OAuth2AuthorizedClient> oldClientMockOpt = Optional.of(oldClientMock);
    replayDefault();
    assertTrue(oauth2CookieService.hasAccessTokenChanged(oldClientMockOpt, clientMock));
    verifyDefault();
  }

  @Test
  public void test_hasAccessTokenChanged_renewToken() {
    OAuth2AuthorizedClient clientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2AccessToken accessTokenMock = createDefaultMock(OAuth2AccessToken.class);
    expect(clientMock.getAccessToken()).andReturn(accessTokenMock).atLeastOnce();
    expect(accessTokenMock.getTokenValue()).andReturn("oldJwtToken").atLeastOnce();
    OAuth2AuthorizedClient oldClientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2AccessToken oldAccessTokenMock = createDefaultMock(OAuth2AccessToken.class);
    expect(oldClientMock.getAccessToken()).andReturn(oldAccessTokenMock).atLeastOnce();
    expect(oldAccessTokenMock.getTokenValue()).andReturn("newJwtToken").atLeastOnce();
    Optional<OAuth2AuthorizedClient> oldClientMockOpt = Optional.of(oldClientMock);
    replayDefault();
    assertTrue(oauth2CookieService.hasAccessTokenChanged(oldClientMockOpt, clientMock));
    verifyDefault();
  }

  @Test
  public void test_hasAccessTokenChanged_validToken_unchanged() {
    OAuth2AuthorizedClient clientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2AccessToken accessTokenMock = createDefaultMock(OAuth2AccessToken.class);
    expect(clientMock.getAccessToken()).andReturn(accessTokenMock).atLeastOnce();
    expect(accessTokenMock.getTokenValue()).andReturn("validJwtToken").atLeastOnce();
    OAuth2AuthorizedClient oldClientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2AccessToken oldAccessTokenMock = createDefaultMock(OAuth2AccessToken.class);
    expect(oldClientMock.getAccessToken()).andReturn(oldAccessTokenMock).atLeastOnce();
    expect(oldAccessTokenMock.getTokenValue()).andReturn("validJwtToken").atLeastOnce();
    Optional<OAuth2AuthorizedClient> oldClientMockOpt = Optional.of(oldClientMock);
    replayDefault();
    assertFalse(oauth2CookieService.hasAccessTokenChanged(oldClientMockOpt, clientMock));
    verifyDefault();
  }

  @Test
  public void test_hasRefreshTokenChanged_bothAccessToken_empty() {
    OAuth2AuthorizedClient clientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    expect(clientMock.getRefreshToken()).andReturn(null).atLeastOnce();
    OAuth2AuthorizedClient oldClientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    expect(oldClientMock.getRefreshToken()).andReturn(null).atLeastOnce();
    Optional<OAuth2AuthorizedClient> oldClientMockOpt = Optional.of(oldClientMock);
    replayDefault();
    assertFalse(oauth2CookieService.hasRefreshTokenChanged(oldClientMockOpt, clientMock));
    verifyDefault();
  }

  @Test
  public void test_hasRefreshTokenChanged_bothAccessValue_empty() {
    OAuth2AuthorizedClient clientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2RefreshToken refreshTokenMock = createDefaultMock(OAuth2RefreshToken.class);
    expect(clientMock.getRefreshToken()).andReturn(refreshTokenMock).atLeastOnce();
    expect(refreshTokenMock.getTokenValue()).andReturn(null).atLeastOnce();
    OAuth2AuthorizedClient oldClientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    expect(oldClientMock.getRefreshToken()).andReturn(null).atLeastOnce();
    Optional<OAuth2AuthorizedClient> oldClientMockOpt = Optional.of(oldClientMock);
    replayDefault();
    assertFalse(oauth2CookieService.hasRefreshTokenChanged(oldClientMockOpt, clientMock));
    verifyDefault();
  }

  @Test
  public void test_hasRefreshTokenChanged_expire_newToken_empty() {
    OAuth2AuthorizedClient clientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2RefreshToken refreshTokenMock = createDefaultMock(OAuth2RefreshToken.class);
    expect(clientMock.getRefreshToken()).andReturn(refreshTokenMock).atLeastOnce();
    expect(refreshTokenMock.getTokenValue()).andReturn(null).atLeastOnce();
    OAuth2AuthorizedClient oldClientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2RefreshToken oldRefreshTokenMock = createDefaultMock(OAuth2RefreshToken.class);
    expect(oldClientMock.getRefreshToken()).andReturn(oldRefreshTokenMock).atLeastOnce();
    expect(oldRefreshTokenMock.getTokenValue()).andReturn("newJwtRefreshToken").atLeastOnce();
    Optional<OAuth2AuthorizedClient> oldClientMockOpt = Optional.of(oldClientMock);
    replayDefault();
    assertTrue(oauth2CookieService.hasRefreshTokenChanged(oldClientMockOpt, clientMock));
    verifyDefault();
  }

  @Test
  public void test_hasRefreshTokenChanged_renewToken() {
    OAuth2AuthorizedClient clientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2RefreshToken refreshTokenMock = createDefaultMock(OAuth2RefreshToken.class);
    expect(clientMock.getRefreshToken()).andReturn(refreshTokenMock).atLeastOnce();
    expect(refreshTokenMock.getTokenValue()).andReturn("oldJwtRefreshToken").atLeastOnce();
    OAuth2AuthorizedClient oldClientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2RefreshToken oldRefreshTokenMock = createDefaultMock(OAuth2RefreshToken.class);
    expect(oldClientMock.getRefreshToken()).andReturn(oldRefreshTokenMock).atLeastOnce();
    expect(oldRefreshTokenMock.getTokenValue()).andReturn("newJwtRefreshToken").atLeastOnce();
    Optional<OAuth2AuthorizedClient> oldClientMockOpt = Optional.of(oldClientMock);
    replayDefault();
    assertTrue(oauth2CookieService.hasRefreshTokenChanged(oldClientMockOpt, clientMock));
    verifyDefault();
  }

  @Test
  public void test_hasRefreshTokenChanged_validToken_unchanged() {
    OAuth2AuthorizedClient clientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2RefreshToken refreshTokenMock = createDefaultMock(OAuth2RefreshToken.class);
    expect(clientMock.getRefreshToken()).andReturn(refreshTokenMock).atLeastOnce();
    expect(refreshTokenMock.getTokenValue()).andReturn("validJwtRefreshToken").atLeastOnce();
    OAuth2AuthorizedClient oldClientMock = createDefaultMock(OAuth2AuthorizedClient.class);
    OAuth2RefreshToken oldRefreshTokenMock = createDefaultMock(OAuth2RefreshToken.class);
    expect(oldClientMock.getRefreshToken()).andReturn(oldRefreshTokenMock).atLeastOnce();
    expect(oldRefreshTokenMock.getTokenValue()).andReturn("validJwtRefreshToken").atLeastOnce();
    Optional<OAuth2AuthorizedClient> oldClientMockOpt = Optional.of(oldClientMock);
    replayDefault();
    assertFalse(oauth2CookieService.hasRefreshTokenChanged(oldClientMockOpt, clientMock));
    verifyDefault();
  }

}
