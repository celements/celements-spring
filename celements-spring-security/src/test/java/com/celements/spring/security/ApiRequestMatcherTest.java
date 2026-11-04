package com.celements.spring.security;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.util.List;

import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

public class ApiRequestMatcherTest {

  @Test
  public void test_forAllPaths_usesRegisteredPrefix() {
    var matcher = mapping("/rest/*").forAllPaths();
    assertTrue(matcher.matches(request("/rest")));
    assertTrue(matcher.matches(request("/rest/events")));
    assertFalse(matcher.matches(request("/api/events")));
    assertFalse(matcher.matches(request("/restaurant/events")));
  }

  @Test
  public void test_forPattern_endpointPathsRemainServletRelative() {
    var mapping = mapping("/rest/*");
    var health = mapping.forPattern("/health/**");
    assertTrue(health.matches(request("/rest/health")));
    assertTrue(health.matches(request("/rest/health/status")));
    assertFalse(health.matches(request("/rest/healthcare")));
    assertFalse(health.matches(request("/api/health/status")));
    var docs = mapping.forPattern("/v3/api-docs");
    assertTrue(docs.matches(request("/rest/v3/api-docs")));
    assertFalse(docs.matches(request("/api/v3/api-docs")));
  }

  @Test
  public void test_forPattern_contextPathAndMultipleMappings() {
    var matcher = mapping("/api/*", "/rest/*").forPattern("/health/**");
    var request = new MockHttpServletRequest("GET", "/wiki/rest/health/status");
    request.setContextPath("/wiki");
    request.setServletPath("/rest");
    request.setPathInfo("/health/status");
    assertTrue(matcher.matches(request));
    assertTrue(matcher.matches(request("/api/health/status")));
  }

  @Test
  public void test_constructor_rejectsMissingOrUnsupportedMappings() {
    assertThrows(IllegalStateException.class, () -> mapping());
    assertThrows(IllegalArgumentException.class, () -> mapping("*.do"));
  }

  private static ApiRequestMatcher mapping(String... mappings) {
    ServletContext servletContext = createMock(ServletContext.class);
    ServletRegistration registration = createMock(ServletRegistration.class);
    expect(servletContext.getServletRegistration("spring-dispatcher")).andReturn(registration);
    expect(registration.getMappings()).andReturn(List.of(mappings));
    replay(servletContext, registration);
    var mapping = new ApiRequestMatcher(servletContext);
    verify(servletContext, registration);
    return mapping;
  }

  private static MockHttpServletRequest request(String path) {
    var request = new MockHttpServletRequest("GET", path);
    request.setServletPath(path);
    return request;
  }
}
