package com.celements.spring.mvc.limiter;

import static com.google.common.base.Preconditions.*;

public record EndpointConcurrencyConfig(int maxConcurrent, int waitMillis) {

  public EndpointConcurrencyConfig {
    checkArgument(maxConcurrent > 0, "Endpoint concurrency limit must be positive");
    checkArgument(waitMillis >= 0, "Endpoint concurrency wait time must be non-negative");
  }
}
