package com.celements.health;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Predicate;
import java.util.function.ToDoubleFunction;

import javax.validation.constraints.NotNull;

import com.celements.health.HealthCheck.Status;
import com.celements.health.HealthReport.CheckSnapshot;

/** Fixed Prometheus gauges; diagnostic reasons never become labels. */
final class HealthMetrics {

  static final String CONTENT_TYPE = "text/plain;version=0.0.4;charset=UTF-8";

  private HealthMetrics() {}

  @NotNull
  static String format(@NotNull HealthReport report, @NotNull Instant jvmStartedAt) {
    var out = new StringBuilder();
    out.append(gauge("celements_health_ready", "Whether this node is ready for routing.",
        report.ready() ? 1 : 0));
    out.append(gauge("celements_health_healthy", "Whether all enabled health checks are healthy.",
        report.isHealthy() ? 1 : 0));
    out.append(gauge("process_start_time_seconds", "JVM start time in seconds since the Unix epoch.",
        epochSeconds(jvmStartedAt)));

    var checks = new TreeMap<>(report.checks());
    checkGauge(out, checks, "celements_health_check_enabled", "Whether the check is enabled.",
        snapshot -> true, snapshot -> snapshot.result().status() == Status.DISABLED ? 0 : 1);
    checkGauge(out, checks, "celements_health_check_success", "Whether the enabled check is healthy.",
        snapshot -> snapshot.result().status() != Status.DISABLED,
        snapshot -> snapshot.isHealthy() ? 1 : 0);
    checkGauge(out, checks, "celements_health_check_duration_seconds",
        "Time spent obtaining the check result, in seconds.",
        snapshot -> true, CheckSnapshot::durationSeconds);
    checkGauge(out, checks, "celements_health_check_observed_timestamp_seconds",
        "Time this request observed the check result, in seconds since the Unix epoch.",
        snapshot -> true, snapshot -> epochSeconds(snapshot.checkedAt()));
    return out.toString();
  }

  @NotNull
  private static String gauge(@NotNull String name, @NotNull String help, @NotNull Number value) {
    return """
        # HELP %1$s %2$s
        # TYPE %1$s gauge
        %1$s %3$s
        """.formatted(name, help, value);
  }

  private static void checkGauge(@NotNull StringBuilder out,
      @NotNull Map<String, CheckSnapshot> checks, @NotNull String name, @NotNull String help,
      @NotNull Predicate<CheckSnapshot> include, @NotNull ToDoubleFunction<CheckSnapshot> value) {
    out.append(gaugeHeader(name, help));
    checks.forEach((id, snapshot) -> {
      if (include.test(snapshot)) {
        out.append(checkSample(name, id, snapshot, value.applyAsDouble(snapshot)));
      }
    });
  }

  @NotNull
  private static String gaugeHeader(@NotNull String name, @NotNull String help) {
    return """
        # HELP %1$s %2$s
        # TYPE %1$s gauge
        """.formatted(name, help);
  }

  @NotNull
  private static String checkSample(@NotNull String name, @NotNull String id,
      @NotNull CheckSnapshot snapshot, double value) {
    var scope = snapshot.scope().name().toLowerCase(Locale.ROOT);
    return """
        %s{check="%s",scope="%s"} %s
        """.formatted(name, escape(id), scope, value);
  }

  @NotNull
  private static String escape(@NotNull String value) {
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace("\"", "\\\"");
  }

  private static double epochSeconds(@NotNull Instant instant) {
    return instant.getEpochSecond() + (instant.getNano() / 1_000_000_000.0);
  }
}
