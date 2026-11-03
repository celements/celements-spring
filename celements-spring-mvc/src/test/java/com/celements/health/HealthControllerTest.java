package com.celements.health;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.lang.management.ManagementFactory;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import javax.servlet.Filter;
import javax.servlet.ServletRegistration;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;

import com.celements.health.HealthCheck.Result;
import com.celements.health.HealthCheck.Scope;
import com.celements.health.HealthCheck.Status;
import com.celements.health.HealthReport.CheckSnapshot;
import com.celements.init.request.ExecutionContextFilter;
import com.celements.spring.security.ApiRequestMatcher;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Standalone MVC verifies wire representations without a wiki, tenant, or authentication. */
public class HealthControllerTest {

  private static final Instant JVM_STARTED_AT = Instant.ofEpochMilli(
      ManagementFactory.getRuntimeMXBean().getStartTime());
  private static final Instant CHECKED_AT = Instant.parse("2026-11-02T12:00:00Z");
  private HealthService service;
  private MockMvc mvc;

  @Before
  public void prepareTest() {
    service = createMock(HealthService.class);
    mvc = MockMvcBuilders.standaloneSetup(new HealthController(service)).build();
  }

  @Test
  public void test_ready_monitoringFailureStillReady() throws Exception {
    expect(service.check(Scope.READINESS))
        .andReturn(reportAsync(
            Map.of("database", snapshot(Status.DOWN, Scope.MONITORING))))
        .once();
    replay(service);
    MvcResult response = performAsync(mvc, management("ready")).andExpect(status().isOk()).andReturn();
    assertTrue(new ObjectMapper().readTree(response.getResponse().getContentAsString())
        .get("ready").asBoolean());
    verify(service);
  }

  @Test
  public void test_ready_noChecksIsUnavailable() throws Exception {
    expect(service.check(Scope.READINESS)).andReturn(reportAsync(Map.of())).once();
    replay(service);
    MvcResult response = performAsync(mvc, management("ready"))
        .andExpect(status().isServiceUnavailable()).andReturn();
    assertFalse(new ObjectMapper().readTree(response.getResponse().getContentAsString())
        .get("ready").asBoolean());
    verify(service);
  }

  @Test
  public void test_status_serializesFullReport() throws Exception {
    CheckSnapshot snapshot = new CheckSnapshot(new Result(Status.DOWN, "Database probe failed"),
        Scope.MONITORING, CHECKED_AT.plusSeconds(10), Duration.ofMillis(125));
    expect(service.check(Scope.MONITORING))
        .andReturn(reportAsync(Map.of("database", snapshot)))
        .once();
    replay(service);
    MvcResult response = performAsync(mvc, management("status"))
        .andExpect(status().isServiceUnavailable())
        .andExpect(header().string("Cache-Control", "no-store")).andReturn();
    JsonNode json = new ObjectMapper().readTree(response.getResponse().getContentAsString());
    assertEquals("DOWN", json.get("status").asText());
    assertTrue(json.get("ready").asBoolean());
    assertEquals(JVM_STARTED_AT.toString(), json.get("jvmStartedAt").asText());
    JsonNode check = json.get("checks").get("database");
    assertEquals(5, check.size());
    assertEquals("DOWN", check.get("status").asText());
    assertEquals("MONITORING", check.get("scope").asText());
    assertEquals(CHECKED_AT.plusSeconds(10).toString(), check.get("checkedAt").asText());
    assertEquals(0.125, check.get("durationSeconds").asDouble(), 0.000001);
    assertEquals("Database probe failed", check.get("reason").asText());
    verify(service);
  }

  @Test
  public void test_status_disabledIsHealthy() throws Exception {
    expect(service.check(Scope.MONITORING))
        .andReturn(reportAsync(
            Map.of("local", snapshot(Status.DISABLED, Scope.READINESS))))
        .once();
    replay(service);
    performAsync(mvc, management("status")).andExpect(status().isOk());
    verify(service);
  }

  @Test(timeout = 5000)
  public void test_status_pendingChecksDoNotBlockServletThread() throws Exception {
    CompletableFuture<HealthReport> pending = new CompletableFuture<>();
    expect(service.check(Scope.MONITORING)).andReturn(pending).once();
    replay(service);
    MvcResult request = mvc.perform(management("status"))
        .andExpect(request().asyncStarted()).andReturn();
    assertFalse(pending.isDone());
    pending.complete(report(Map.of("local", snapshot(Status.UP, Scope.READINESS))));
    mvc.perform(asyncDispatch(request)).andExpect(status().isOk());
    verify(service);
  }

  @Test
  public void test_metrics_failedHealthStillReturnsValidMetrics() throws Exception {
    CheckSnapshot snapshot = new CheckSnapshot(new Result(Status.DOWN, "private diagnostic detail"),
        Scope.READINESS, CHECKED_AT, Duration.ofMillis(250));
    expect(service.check(Scope.MONITORING))
        .andReturn(reportAsync(Map.of("kafka", snapshot)))
        .once();
    replay(service);
    MvcResult response = performAsync(mvc, management("metrics")).andExpect(status().isOk())
        .andExpect(content().contentType(HealthMetrics.CONTENT_TYPE)).andReturn();
    String metrics = response.getResponse().getContentAsString();
    assertTrue(metrics.contains("celements_health_ready 0\n"));
    assertTrue(metrics.contains("process_start_time_seconds "
        + (JVM_STARTED_AT.getEpochSecond() + JVM_STARTED_AT.getNano() / 1_000_000_000.0)
        + "\n"));
    assertTrue(metrics.contains("celements_health_check_success{check=\"kafka\",scope=\"readiness\"} 0.0\n"));
    assertTrue(metrics.contains("celements_health_check_duration_seconds{check=\"kafka\",scope=\"readiness\"} 0.25\n"));
    assertFalse(metrics.contains("private diagnostic detail"));
    assertTrue(metrics.endsWith("\n"));
    verify(service);
  }

  @Test
  public void test_metrics_escapesLabelsAndOmitsDisabledFailures() {
    CheckSnapshot disabled = new CheckSnapshot(new Result(Status.DISABLED, "disabled"),
        Scope.READINESS, CHECKED_AT, Duration.ZERO);
    String metrics = HealthMetrics.format(report(
        Map.of("a\"\\\nb", disabled)), JVM_STARTED_AT);
    assertTrue(metrics.contains("celements_health_check_enabled{check=\"a\\\"\\\\\\nb\",scope=\"readiness\"} 0.0\n"));
    assertFalse(metrics.contains("celements_health_check_success{"));
    assertTrue(metrics.contains("celements_health_healthy 1\n"));
  }

  @Test
  public void test_requestPath_exclusionBypassesWikiAndSecurityEnforcesConnector() throws Exception {
    expect(service.check(Scope.MONITORING))
        .andReturn(reportAsync(Map.of("local", snapshot(Status.UP, Scope.READINESS))))
        .once();
    replay(service);
    try (var context = new AnnotationConfigWebApplicationContext()) {
      ServletRegistration registration = createMock(ServletRegistration.class);
      expect(registration.getMappings()).andReturn(List.of("/rest/*"));
      replay(registration);
      context.setServletContext(new MockServletContext() {
        @Override
        public ServletRegistration getServletRegistration(String name) {
          assertEquals("spring-dispatcher", name);
          return registration;
        }
      });
      context.register(SecurityConfig.class, HealthConfig.class, ApiRequestMatcher.class,
          ExecutionContextFilter.class);
      context.refresh();
      var executionFilter = new DelegatingFilterProxy("executionContextFilter", context);
      executionFilter.init(new MockFilterConfig(context.getServletContext(), "executionContextFilter"));
      MockMvc securedMvc = MockMvcBuilders.standaloneSetup(new HealthController(service))
          .addFilters(executionFilter, context.getBean("springSecurityFilterChain", Filter.class))
          .build();

      performAsync(securedMvc, management("/rest", "status")
          .header("Authorization", "Bearer invalid"))
          .andExpect(status().isOk());
      securedMvc.perform(get("/rest/health/status").with(request -> {
        request.setServletPath("/rest");
        request.setPathInfo("/health/status");
        request.setServerPort(9090);
        request.setLocalPort(8080);
        request.addHeader("X-Forwarded-Port", "9090");
        return request;
      })).andExpect(status().isForbidden());
    }
    verify(service);
  }

  @Configuration
  @EnableWebSecurity
  static class SecurityConfig {}

  private static ResultActions performAsync(MockMvc mvc, MockHttpServletRequestBuilder builder)
      throws Exception {
    MvcResult pending = mvc.perform(builder).andExpect(request().asyncStarted()).andReturn();
    return mvc.perform(asyncDispatch(pending));
  }

  private static MockHttpServletRequestBuilder management(String endpoint) {
    return management("/api", endpoint);
  }

  private static MockHttpServletRequestBuilder management(String servletPath, String endpoint) {
    return get(servletPath + "/health/" + endpoint).with(request -> {
      request.setServletPath(servletPath);
      request.setPathInfo("/health/" + endpoint);
      request.setLocalPort(9090);
      request.setServerName("unknown-tenant.invalid");
      return request;
    });
  }

  private static CheckSnapshot snapshot(Status status, Scope scope) {
    return new CheckSnapshot(new Result(status, ""), scope, CHECKED_AT, Duration.ZERO);
  }

  private static HealthReport report(Map<String, CheckSnapshot> checks) {
    return new HealthReport(checks);
  }

  private static CompletionStage<HealthReport> reportAsync(Map<String, CheckSnapshot> checks) {
    return CompletableFuture.completedFuture(report(checks));
  }
}
