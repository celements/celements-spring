package com.celements.store.api;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.aop.framework.Advised;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.server.ResponseStatusException;

import com.celements.auth.user.User;
import com.celements.auth.user.UserService;
import com.celements.common.test.AbstractComponentTest;
import com.celements.rights.access.IRightsAccessFacadeRole;
import com.celements.spring.security.oauth2.IdentityService;
import com.celements.store.DocumentCacheStore;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.user.api.XWikiUser;

public class DocumentCacheControllerTest extends AbstractComponentTest {

  private User user;
  private DocumentCacheController controller;

  @Before
  public void prepareTest() throws Exception {
    registerComponentMock(DocumentCacheStore.class);
    registerComponentMock(IRightsAccessFacadeRole.class);
    registerComponentMock(UserService.class);
    user = createDefaultMock(User.class);
    controller = getBeanTarget(DocumentCacheController.class);
  }

  @SuppressWarnings("unchecked")
  private <T> T getBeanTarget(Class<T> beanClass) throws Exception {
    T bean = getBeanFactory().getBean(beanClass);
    if (bean instanceof Advised advised) {
      return (T) advised.getTargetSource().getTarget();
    }
    return bean;
  }

  @Test
  public void test_allApiMethods_requireSuperAdmin() throws Exception {
    List<Method> apiMethods = Arrays.stream(DocumentCacheController.class.getDeclaredMethods())
        .filter(method -> AnnotatedElementUtils.hasAnnotation(method, RequestMapping.class))
        .toList();
    assertFalse("controller must expose API methods", apiMethods.isEmpty());
    XWikiUser xuser = new XWikiUser("xwiki:XWiki.Admin", true);

    expect(getMock(XWiki.class).checkAuth(same(getXContext()))).andReturn(xuser)
        .times(apiMethods.size());
    expect(getMock(UserService.class).getUser(eq("xwiki:XWiki.Admin"))).andReturn(user)
        .times(apiMethods.size());
    expect(getMock(IRightsAccessFacadeRole.class).isSuperAdmin(same(user))).andReturn(false)
        .times(apiMethods.size());
    replayDefault();

    for (Method method : apiMethods) {
      InvocationTargetException exception = assertThrows(method.toString(),
          InvocationTargetException.class, () -> method.invoke(controller));
      assertTrue(exception.getCause() instanceof ResponseStatusException);
      assertEquals(HttpStatus.FORBIDDEN,
          ((ResponseStatusException) exception.getCause()).getStatus());
    }

    verifyDefault();
  }

  @Configuration
  static class TestConfig {

    @Bean
    IdentityService identityService() {
      IdentityService identityService = createNiceMock(IdentityService.class);
      replay(identityService);
      return identityService;
    }
  }

}
