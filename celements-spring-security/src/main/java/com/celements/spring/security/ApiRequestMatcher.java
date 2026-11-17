package com.celements.spring.security;

import static com.google.common.base.Preconditions.*;

import java.util.List;

import javax.inject.Inject;
import javax.servlet.ServletContext;
import javax.validation.constraints.NotNull;

import org.springframework.context.annotation.Profile;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

/** Builds servlet-relative request matchers from the container's Spring servlet registration. */
@Component
@Profile("!test")
public class ApiRequestMatcher {

  private final List<String> prefixes;

  @Inject
  public ApiRequestMatcher(@NotNull ServletContext servletContext) {
    var registration = servletContext.getServletRegistration("spring-dispatcher");
    checkState(registration != null, "Missing spring-dispatcher servlet registration");
    prefixes = registration.getMappings().stream().map(this::pathPrefix).toList();
    checkState(!prefixes.isEmpty(), "Missing spring-dispatcher servlet mapping");
  }

  @NotNull
  public RequestMatcher forAllPaths() {
    return forPattern("/**");
  }

  @NotNull
  public RequestMatcher forPattern(@NotNull String pathPattern) {
    checkArgument(pathPattern.startsWith("/"), "Expected servlet-relative path [%s]", pathPattern);
    return new OrRequestMatcher(prefixes.stream()
        .map(prefix -> new AntPathRequestMatcher(prefix + pathPattern))
        .toArray(RequestMatcher[]::new));
  }

  @NotNull
  private String pathPrefix(@NotNull String mapping) {
    checkArgument(mapping.endsWith("/*"), "Expected Spring servlet path mapping [%s]", mapping);
    return mapping.substring(0, mapping.length() - 2);
  }
}
