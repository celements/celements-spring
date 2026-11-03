package com.celements.health;

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CompletionStage;

import javax.inject.Inject;
import javax.validation.constraints.NotNull;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.celements.health.HealthCheck.Scope;
import com.celements.health.HealthCheck.Status;
import com.celements.health.HealthReport.CheckSnapshot;

import one.util.streamex.EntryStream;

/** HTTP representations of the same application health report. */
@RestController
@RequestMapping(HealthConfig.PATH)
public class HealthController {

  private final HealthService healthService;
  private final Instant jvmStartedAt;

  @Inject
  public HealthController(@NotNull HealthService healthService) {
    this.healthService = healthService;
    jvmStartedAt = Instant.ofEpochMilli(ManagementFactory.getRuntimeMXBean().getStartTime());
  }

  @GetMapping(value = "/ready", produces = MediaType.APPLICATION_JSON_VALUE)
  @NotNull
  public CompletionStage<@NotNull ResponseEntity<ReadyResponse>> ready() {
    return healthService.check(Scope.READINESS).thenApply(report -> ResponseEntity
        .status(report.ready() ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE)
        .cacheControl(CacheControl.noStore())
        .body(new ReadyResponse(report.ready())));
  }

  public record ReadyResponse(boolean ready) {}

  @GetMapping(value = "/status", produces = MediaType.APPLICATION_JSON_VALUE)
  @NotNull
  public CompletionStage<@NotNull ResponseEntity<StatusResponse>> status() {
    return healthService.check(Scope.MONITORING).thenApply(report -> ResponseEntity
        .status(report.isHealthy() ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE)
        .cacheControl(CacheControl.noStore())
        .body(new StatusResponse(report, jvmStartedAt)));
  }

  public record StatusResponse(
      @NotNull Status status,
      boolean ready,
      @NotNull String jvmStartedAt,
      @NotNull Map<@NotNull String, @NotNull CheckResponse> checks) {

    StatusResponse(@NotNull HealthReport report, @NotNull Instant jvmStartedAt) {
      this(report.status(), report.ready(), jvmStartedAt.toString(),
          EntryStream.of(report.checks())
              .mapValues(CheckResponse::new)
              .toImmutableMap());
    }
  }

  public record CheckResponse(
      @NotNull Status status,
      @NotNull Scope scope,
      @NotNull String checkedAt,
      double durationSeconds,
      @NotNull String reason) {

    CheckResponse(@NotNull CheckSnapshot snapshot) {
      this(
          snapshot.result().status(),
          snapshot.scope(),
          snapshot.checkedAt().toString(),
          snapshot.durationSeconds(),
          snapshot.result().reason());
    }
  }

  @GetMapping(value = "/metrics", produces = HealthMetrics.CONTENT_TYPE)
  @NotNull
  public CompletionStage<@NotNull ResponseEntity<String>> metrics() {
    return healthService.check(Scope.MONITORING).thenApply(report -> ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(HealthMetrics.CONTENT_TYPE))
        .cacheControl(CacheControl.noStore())
        .body(HealthMetrics.format(report, jvmStartedAt)));
  }

}
