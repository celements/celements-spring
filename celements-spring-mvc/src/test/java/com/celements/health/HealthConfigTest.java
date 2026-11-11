package com.celements.health;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import javax.servlet.Filter;
import javax.servlet.ServletRegistration;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import com.celements.spring.security.ApiRequestMatcher;

/** Endpoint security belongs to the MVC health configuration. */
public class HealthConfigTest {

  private AnnotationConfigWebApplicationContext context;
  private Filter security;

  @Before
  public void prepareTest() {
    prepareContext("/api/*");
  }

  private void prepareContext(String mapping) {
    ServletRegistration registration = createMock(ServletRegistration.class);
    expect(registration.getMappings()).andReturn(List.of(mapping));
    replay(registration);
    context = new AnnotationConfigWebApplicationContext();
    context.setServletContext(new MockServletContext() {
      @Override
      public ServletRegistration getServletRegistration(String name) {
        assertEquals("spring-dispatcher", name);
        return registration;
      }
    });
    context.register(HealthConfig.class, ApiRequestMatcher.class, FallbackConfig.class);
    context.refresh();
    security = context.getBean("springSecurityFilterChain", Filter.class);
  }

  @After
  public void destroy() {
    context.close();
  }

  @Test
  public void test_healthFilterChain_managementSkipsAuthentication() throws Exception {
    for (var path : new String[] { "/api/health", "/api/health/", "/api/health/ready",
        "/api/health/status", "/api/health/metrics" }) {
      var request = request(path, 9090);
      request.setServerName("unknown-tenant.invalid");
      request.addHeader("Authorization", "Bearer deliberately-invalid");
      var response = new MockHttpServletResponse();
      security.doFilter(request, response, (req, res) -> ((HttpServletResponse) res).setStatus(204));
      assertEquals(204, response.getStatus());
      assertNull(request.getSession(false));
    }
    assertEquals(0, context.getBean(AtomicInteger.class).get());
  }

  @Test
  public void test_healthFilterChain_contextPath() throws Exception {
    var request = request("/wiki/api/health/status", 9090);
    request.setContextPath("/wiki");
    request.setServletPath("/api");
    request.setPathInfo("/health/status");
    var response = new MockHttpServletResponse();
    security.doFilter(request, response, (req, res) -> ((HttpServletResponse) res).setStatus(204));
    assertEquals(204, response.getStatus());
    assertEquals(0, context.getBean(AtomicInteger.class).get());
  }

  @Test
  public void test_healthFilterChain_usesConfiguredServletMapping() throws Exception {
    context.close();
    prepareContext("/rest/*");
    var request = request("/rest/health/status", 9090);
    request.addHeader("Authorization", "Bearer deliberately-invalid");
    var response = new MockHttpServletResponse();
    security.doFilter(request, response, (req, res) -> ((HttpServletResponse) res).setStatus(204));
    assertEquals(204, response.getStatus());
    assertEquals(0, context.getBean(AtomicInteger.class).get());

    var denied = new MockHttpServletResponse();
    security.doFilter(request("/rest/health/status", 8080), denied,
        (req, res) -> fail("Public health request was allowed"));
    assertEquals(403, denied.getStatus());
    security.doFilter(request("/api/health/status", 9090), new MockHttpServletResponse(),
        (req, res) -> ((HttpServletResponse) res).setStatus(204));
    assertEquals(1, context.getBean(AtomicInteger.class).get());
  }

  @Test
  public void test_healthFilterChain_publicPortCannotBeSpoofed() throws Exception {
    for (var endpoint : new String[] { "ready", "status", "metrics" }) {
      var request = request("/api/health/" + endpoint, 8080);
      request.setServerPort(9090);
      request.addHeader("Host", "localhost:9090");
      request.addHeader("X-Forwarded-Port", "9090");
      var response = new MockHttpServletResponse();
      security.doFilter(request, response, (req, res) -> fail("Public health request was allowed"));
      assertEquals(403, response.getStatus());
    }
    assertEquals(0, context.getBean(AtomicInteger.class).get());
  }

  @Test
  public void test_healthFilterChain_otherPathsUseExistingChain() throws Exception {
    for (String path : new String[] { "/api/events", "/api/healthcare", "/health",
        "/operations/status" }) {
      MockHttpServletResponse response = new MockHttpServletResponse();
      security.doFilter(request(path, 8080), response,
          (req, res) -> ((HttpServletResponse) res).setStatus(204));
      assertEquals(204, response.getStatus());
    }
    assertEquals(4, context.getBean(AtomicInteger.class).get());
  }

  private static MockHttpServletRequest request(String path, int port) {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    request.setServletPath(path);
    request.setLocalPort(port);
    return request;
  }

  @Configuration
  @EnableWebSecurity
  static class FallbackConfig {

    @Bean
    @Qualifier("executionContextExclusion")
    Predicate<HttpServletRequest> operationsRequests() {
      return request -> request.getRequestURI().equals("/operations/status");
    }

    @Bean
    AtomicInteger fallbackCalls() {
      return new AtomicInteger();
    }

    @Bean
    @Order(10)
    SecurityFilterChain fallback(HttpSecurity http, AtomicInteger fallbackCalls) throws Exception {
      return http.authorizeHttpRequests(authorize -> authorize.anyRequest().access((auth, context) -> {
        fallbackCalls.incrementAndGet();
        return new AuthorizationDecision(true);
      })).build();
    }
  }
}
