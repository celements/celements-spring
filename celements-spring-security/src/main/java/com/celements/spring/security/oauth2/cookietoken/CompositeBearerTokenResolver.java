package com.celements.spring.security.oauth2.cookietoken;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

public class CompositeBearerTokenResolver implements BearerTokenResolver {

  private final BearerTokenResolver headerResolver = new DefaultBearerTokenResolver();
  private final BearerTokenResolver cookieResolver;

  public CompositeBearerTokenResolver(BearerTokenResolver cookie) {
    this.cookieResolver = cookie;
  }

  @Override
  public String resolve(HttpServletRequest request) {
    LinkedHashSet<String> tokens = Stream.of(cookieResolver, headerResolver)
        .map(resolver -> resolver.resolve(request))
        .filter(Objects::nonNull)
        .collect(Collectors.toCollection(LinkedHashSet::new));
    if (tokens.size() > 1) {
      throw new OAuth2AuthenticationException(
          BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request"));
    }
    return tokens.stream().findFirst().orElse(null);
  }
}
