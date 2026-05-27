package com.celements.spring.security;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.springframework.aop.framework.Advised;
import org.springframework.stereotype.Component;

import com.celements.auth.user.User;
import com.celements.auth.user.UserInstantiationException;
import com.celements.auth.user.UserService;
import com.celements.common.test.AbstractComponentTest;
import com.celements.rights.access.IRightsAccessFacadeRole;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiUser;

public class AuthenticatedBaseControllerTest extends AbstractComponentTest {

  private TestController controller;
  private UserService userServiceMock;
  private User userMock;

  @Component
  static class TestController extends AuthenticatedBaseController {
    // only exists to make the abstract class instantiable for tests
  }

  @Before
  public void prepare() throws Exception {
    userServiceMock = registerComponentMock(UserService.class);
    registerComponentMock(IRightsAccessFacadeRole.class);
    userMock = createDefaultMock(User.class);
    controller = getBeanTarget(getBeanFactory().createBean(TestController.class));
  }

  /**
   * Returns the proxied bean's target so these tests exercise {@link AuthenticatedBaseController}
   * method logic directly instead of Spring Security method interceptors.
   */
  @SuppressWarnings("unchecked")
  private <T> T getBeanTarget(T bean) throws Exception {
    if (bean instanceof Advised advised) {
      return (T) advised.getTargetSource().getTarget();
    }
    return bean;
  }

  @Test
  public void test_checkAuth_success() throws Exception {
    String userName = "XWiki.TestUser";
    XWikiUser xuser = new XWikiUser(userName);
    expect(getXContext().getWiki().checkAuth(same(getXContext()))).andReturn(xuser);
    expect(userServiceMock.getUser(eq(userName))).andReturn(userMock);
    replayDefault();

    Optional<User> result = controller.checkAuth();

    verifyDefault();
    assertTrue(result.isPresent());
    assertSame(userMock, result.get());
    assertEquals(userName, getXContext().getUser());
  }

  @Test
  public void test_checkAuth_UserInstantiationException_xcontextUnchanged() throws Exception {
    String userName = "XWiki.DeletedUser";
    String originalUser = getXContext().getUser();
    XWikiUser xuser = new XWikiUser(userName);
    expect(getXContext().getWiki().checkAuth(same(getXContext()))).andReturn(xuser);
    expect(userServiceMock.getUser(eq(userName)))
        .andThrow(new UserInstantiationException("No user object on doc: " + userName));
    replayDefault();

    Optional<User> result = controller.checkAuth();

    verifyDefault();
    assertTrue("should return empty on UserInstantiationException", result.isEmpty());
    assertEquals("xcontext user must not be changed when getUser throws",
        originalUser, getXContext().getUser());
  }

  @Test
  public void test_checkAuth_guestUser_returnsEmpty() throws Exception {
    String originalUser = getXContext().getUser();
    expect(getXContext().getWiki().checkAuth(same(getXContext()))).andReturn(null);
    replayDefault();

    Optional<User> result = controller.checkAuth();

    verifyDefault();
    assertTrue("should return empty for guest (null XWikiUser)", result.isEmpty());
    assertEquals("xcontext user must not be changed for guest",
        originalUser, getXContext().getUser());
  }

  @Test
  public void test_checkAuth_XWikiException_returnsEmpty() throws Exception {
    String originalUser = getXContext().getUser();
    expect(getXContext().getWiki().checkAuth(same(getXContext())))
        .andThrow(new XWikiException());
    replayDefault();

    Optional<User> result = controller.checkAuth();

    verifyDefault();
    assertTrue("should return empty on XWikiException", result.isEmpty());
    assertEquals("xcontext user must not be changed on XWikiException",
        originalUser, getXContext().getUser());
  }

  @Test
  public void test_checkAuth_predicate_success() throws Exception {
    String userName = "XWiki.TestUser";
    XWikiUser xuser = new XWikiUser(userName);
    expect(getXContext().getWiki().checkAuth(same(getXContext()))).andReturn(xuser);
    expect(userServiceMock.getUser(eq(userName))).andReturn(userMock);
    replayDefault();

    boolean result = controller.checkAuth(user -> user == userMock);

    verifyDefault();
    assertTrue("predicate matching the user should return true", result);
  }

  @Test
  public void test_checkAuth_predicate_noMatch() throws Exception {
    String userName = "XWiki.TestUser";
    XWikiUser xuser = new XWikiUser(userName);
    expect(getXContext().getWiki().checkAuth(same(getXContext()))).andReturn(xuser);
    expect(userServiceMock.getUser(eq(userName))).andReturn(userMock);
    replayDefault();

    boolean result = controller.checkAuth(user -> false);

    verifyDefault();
    assertFalse("predicate rejecting the user should return false", result);
  }

}
