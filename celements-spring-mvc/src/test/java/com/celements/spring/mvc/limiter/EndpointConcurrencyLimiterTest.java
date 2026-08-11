package com.celements.spring.mvc.limiter;

import static org.junit.Assert.*;
import static org.springframework.http.HttpStatus.*;
import static java.util.concurrent.Executors.*;
import static java.util.concurrent.TimeUnit.*;

import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;

import com.celements.common.test.AbstractComponentTest;
import com.celements.spring.mvc.limiter.EndpointConcurrencyConfig;
import com.celements.spring.mvc.limiter.EndpointConcurrencyLimit;
import com.celements.spring.mvc.limiter.EndpointConcurrencyLimiter;

public class EndpointConcurrencyLimiterTest extends AbstractComponentTest {

  private EndpointConcurrencyLimiter limiter;

  @Before
  public void prepareTest() {
    limiter = getBeanFactory().getBean(EndpointConcurrencyLimiter.class);
  }

  @Test
  public void test_unannotatedHandlersAreUnlimited() throws Exception {
    assertTrue(limiter.preHandle(new MockHttpServletRequest(), new MockHttpServletResponse(),
        handlerMethod("unlimitedEndpoint")));
    assertTrue(limiter.preHandle(
        new MockHttpServletRequest(), new MockHttpServletResponse(), new Object()));
  }

  @Test
  public void test_sameLimitSharesCapacityAndReleasesAfterCompletion() throws Exception {
    var request = new MockHttpServletRequest();
    assertTrue(limiter.preHandle(
        request, new MockHttpServletResponse(), handlerMethod("limitedEndpoint")));

    var response = new MockHttpServletResponse();
    assertFalse(limiter.preHandle(
        new MockHttpServletRequest(), response, handlerMethod("limitedEndpoint")));
    assertEquals(SERVICE_UNAVAILABLE.value(), response.getStatus());

    limiter.afterCompletion(request, null, handlerMethod("limitedEndpoint"), null);
    assertTrue(limiter.preHandle(new MockHttpServletRequest(), new MockHttpServletResponse(),
        handlerMethod("limitedEndpoint")));
  }

  @Test
  public void test_waitsForCapacity() throws Exception {
    var waitingLimiter = new EndpointConcurrencyLimiter(Map.of(
        "search", new EndpointConcurrencyConfig(1, 1000)));
    var request = new MockHttpServletRequest();
    var handler = handlerMethod("limitedEndpoint");
    assertTrue(waitingLimiter.preHandle(request, new MockHttpServletResponse(), handler));

    var executor = newSingleThreadScheduledExecutor();
    try {
      executor.schedule(
          () -> waitingLimiter.afterCompletion(request, null, handler, null), 50, MILLISECONDS);
      assertTrue(waitingLimiter.preHandle(
          new MockHttpServletRequest(), new MockHttpServletResponse(), handler));
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  public void test_differentLimitsHaveIndependentCapacity() throws Exception {
    assertTrue(limiter.preHandle(new MockHttpServletRequest(), new MockHttpServletResponse(),
        handlerMethod("limitedEndpoint")));
    assertTrue(limiter.preHandle(new MockHttpServletRequest(), new MockHttpServletResponse(),
        handlerMethod("otherLimitedEndpoint")));
  }

  @Test
  public void test_missingConfigFailsClosed() throws Exception {
    assertThrows(IllegalStateException.class, () -> limiter.preHandle(
        new MockHttpServletRequest(), new MockHttpServletResponse(),
        handlerMethod("missingLimitEndpoint")));
  }

  @Test
  public void test_classAnnotation() throws Exception {
    var request = new MockHttpServletRequest();
    var handler = new HandlerMethod(
        new LimitedController(), LimitedController.class.getMethod("limitedEndpoint"));

    assertTrue(limiter.preHandle(request, new MockHttpServletResponse(), handler));
    assertFalse(limiter.preHandle(
        new MockHttpServletRequest(), new MockHttpServletResponse(), handler));
  }

  @Test
  public void test_configRejectsNonPositiveConcurrency() {
    assertThrows(IllegalArgumentException.class, () -> new EndpointConcurrencyConfig(0, 0));
    assertThrows(IllegalArgumentException.class, () -> new EndpointConcurrencyConfig(-1, 0));
    assertThrows(IllegalArgumentException.class, () -> new EndpointConcurrencyConfig(1, -1));
  }

  private HandlerMethod handlerMethod(String name) {
    try {
      return new HandlerMethod(new TestController(), TestController.class.getMethod(name));
    } catch (NoSuchMethodException exc) {
      throw new IllegalArgumentException(exc);
    }
  }

  private static class TestController {

    public void unlimitedEndpoint() {}

    @EndpointConcurrencyLimit("search")
    public void limitedEndpoint() {}

    @EndpointConcurrencyLimit("other")
    public void otherLimitedEndpoint() {}

    @EndpointConcurrencyLimit("missing")
    public void missingLimitEndpoint() {}
  }

  @EndpointConcurrencyLimit("search")
  private static class LimitedController {

    public void limitedEndpoint() {}
  }

  @Configuration
  static class TestConfig {

    @Bean("search")
    EndpointConcurrencyConfig searchLimiterConfig() {
      return new EndpointConcurrencyConfig(1, 0);
    }

    @Bean("other")
    EndpointConcurrencyConfig otherLimiterConfig() {
      return new EndpointConcurrencyConfig(1, 0);
    }

    @Bean
    @Primary
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    EndpointConcurrencyLimiter endpointConcurrencyLimiter(
        Map<String, EndpointConcurrencyConfig> configs) {
      return new EndpointConcurrencyLimiter(configs);
    }
  }
}
