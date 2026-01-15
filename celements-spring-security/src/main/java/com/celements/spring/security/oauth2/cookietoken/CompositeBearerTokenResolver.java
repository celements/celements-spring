package com.celements.spring.security.oauth2.cookietoken;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

public class CompositeBearerTokenResolver implements BearerTokenResolver {

  private final BearerTokenResolver headerResolver = new DefaultBearerTokenResolver();
  private final BearerTokenResolver cookieResolver;

  public CompositeBearerTokenResolver(BearerTokenResolver cookieResolver) {
    this.cookieResolver = cookieResolver;
  }

  @Override
  public String resolve(HttpServletRequest request) {
    LinkedHashSet<String> tokens = Stream.of(headerResolver, cookieResolver)
        .map(resolver -> resolver.resolve(request))
        .filter(Objects::nonNull)
        .collect(Collectors.toCollection(LinkedHashSet::new));
    return tokens.stream().findFirst().orElse(null);
  }
}
