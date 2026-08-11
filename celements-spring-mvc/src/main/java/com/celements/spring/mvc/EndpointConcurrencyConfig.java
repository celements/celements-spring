package com.celements.spring.mvc;

public record EndpointConcurrencyConfig(int maxConcurrent, int waitMillis) {

  public EndpointConcurrencyConfig {
    if (maxConcurrent <= 0) {
      throw new IllegalArgumentException("Endpoint concurrency limit must be positive");
    }
    if (waitMillis < 0) {
      throw new IllegalArgumentException("Endpoint concurrency wait time must be non-negative");
    }
  }
}
