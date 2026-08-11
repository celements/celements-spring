package com.celements.spring.mvc.limiter;

import static com.google.common.base.Preconditions.*;
import static java.util.concurrent.TimeUnit.*;
import static org.springframework.core.annotation.AnnotatedElementUtils.*;
import static org.springframework.http.HttpStatus.*;

import java.io.IOException;
import java.lang.reflect.AnnotatedElement;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Semaphore;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;

import com.celements.spring.mvc.CelMvcInterceptor;

import one.util.streamex.EntryStream;

@Component
public class EndpointConcurrencyLimiter implements CelMvcInterceptor {

  private final Map<String, EndpointConcurrencyConfig> configs;
  private final Map<String, Semaphore> limiters;

  @Inject
  public EndpointConcurrencyLimiter(Optional<Map<String, EndpointConcurrencyConfig>> configs) {
    this(configs.orElseGet(Map::of));
  }

  EndpointConcurrencyLimiter(Map<String, EndpointConcurrencyConfig> configs) {
    this.configs = Map.copyOf(configs);
    this.limiters = EntryStream.of(configs)
        .mapValues(config -> new Semaphore(config.maxConcurrent()))
        .toMap();
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws IOException {
    var name = getConcurrencyLimit(handler).orElse(null);
    if ((name == null) || tryAcquire(name)) {
      return true;
    }
    response.sendError(SERVICE_UNAVAILABLE.value(), "Endpoint concurrency limit exhausted");
    return false;
  }

  private boolean tryAcquire(String name) {
    try {
      var config = configs.get(name);
      checkState(config != null, "Missing EndpointConcurrencyConfig [%s]", name);
      return limiters.get(name).tryAcquire(config.waitMillis(), MILLISECONDS);
    } catch (InterruptedException exc) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  @Override
  public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
      Object handler, Exception exc) {
    getConcurrencyLimit(handler)
        .map(limiters::get)
        .ifPresent(Semaphore::release);
  }

  private Optional<String> getConcurrencyLimit(Object handler) {
    if (!(handler instanceof HandlerMethod methodHandler)) {
      return Optional.empty();
    }
    return findAnnotation(methodHandler.getMethod())
        .or(() -> findAnnotation(methodHandler.getBeanType()))
        .map(EndpointConcurrencyLimit::value);
  }

  private Optional<EndpointConcurrencyLimit> findAnnotation(AnnotatedElement element) {
    return Optional.ofNullable(findMergedAnnotation(element, EndpointConcurrencyLimit.class));
  }
}
