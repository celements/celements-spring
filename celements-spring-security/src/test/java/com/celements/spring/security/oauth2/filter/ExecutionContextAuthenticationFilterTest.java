package com.celements.spring.security.oauth2.filter;

import static com.celements.execution.XWikiExecutionProp.*;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import org.xwiki.context.Execution;

import com.celements.auth.MainAdminConfig;
import com.celements.auth.user.UserService;
import com.celements.common.test.AbstractComponentTest;
import com.xpn.xwiki.user.api.XWikiUser;

public class ExecutionContextAuthenticationFilterTest extends AbstractComponentTest {

  private ExecutionContextAuthenticationFilter filter;
  private UserService userService;
  private MainAdminConfig mainAdminConfig;

  @Before
  public void prepareTest() throws Exception {
    userService = createDefaultMock(UserService.class);
    mainAdminConfig = createDefaultMock(MainAdminConfig.class);
    filter = new ExecutionContextAuthenticationFilter(userService, mainAdminConfig,
        getBeanFactory().getBean(Execution.class));
  }

  @After
  public void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  public void test_doFilterInternal_autoLoginAdmin() throws Exception {
    HttpServletRequest request = createDefaultMock(HttpServletRequest.class);
    HttpServletResponse response = createDefaultMock(HttpServletResponse.class);
    FilterChain chain = createDefaultMock(FilterChain.class);
    XWikiUser xwikiUser = new XWikiUser("xwiki:XWiki.Admin", true);
    expect(mainAdminConfig.isAutoLoginEnabled()).andReturn(true);
    expect(mainAdminConfig.getXWikiUser()).andReturn(xwikiUser);
    chain.doFilter(request, response);
    replayDefault();

    filter.doFilterInternal(request, response, chain);

    verifyDefault();
    assertEquals("xwiki:XWiki.Admin",
        SecurityContextHolder.getContext().getAuthentication().getName());
    assertTrue(SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
    assertSame(xwikiUser, getBeanFactory().getBean(Execution.class).getContext()
        .get(XWIKI_USER).orElseThrow());
  }

  @Test
  public void test_doFilterInternal_autoLoginDisabled() throws Exception {
    HttpServletRequest request = createDefaultMock(HttpServletRequest.class);
    HttpServletResponse response = createDefaultMock(HttpServletResponse.class);
    FilterChain chain = createDefaultMock(FilterChain.class);
    expect(mainAdminConfig.isAutoLoginEnabled()).andReturn(false);
    chain.doFilter(request, response);
    replayDefault();

    filter.doFilterInternal(request, response, chain);

    verifyDefault();
    assertNull(SecurityContextHolder.getContext().getAuthentication());
  }

}
