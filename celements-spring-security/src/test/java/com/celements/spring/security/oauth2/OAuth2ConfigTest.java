package com.celements.spring.security.oauth2;

import static org.easymock.EasyMock.*;

import java.util.Optional;

import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import com.celements.common.test.AbstractComponentTest;
import com.celements.spring.security.oauth2.cookietoken.CookieTokenService;

public class OAuth2ConfigTest extends AbstractComponentTest {

  private OAuth2Config config;

  @Before
  public void prepareTest() throws Exception {
    registerComponentMocks(IdentityService.class, CookieTokenService.class);
    config = getBeanFactory().getBean(OAuth2Config.class);
  }

  @Test
  public void test_revokeRefreshTokenHandler_noRefreshTokenSkipsRevocation() throws Exception {
    var request = new MockHttpServletRequest("POST", "/logout");
    var response = createDefaultMock(HttpServletResponse.class);
    CookieTokenService tokenService = getMock(CookieTokenService.class);
    expect(tokenService.getRefreshToken(request)).andReturn(Optional.empty());
    replayDefault();
    config.revokeRefreshTokenHandler(tokenService).logout(request, response, null);
    verifyDefault();
  }
}
