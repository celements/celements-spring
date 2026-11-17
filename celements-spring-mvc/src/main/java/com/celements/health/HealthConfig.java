package com.celements.health;

import java.util.function.Predicate;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import com.celements.spring.security.ApiRequestMatcher;

/** Management probes must work without tenant resolution, sessions, or OAuth processing. */
@Configuration
@Profile("!test")
public class HealthConfig {

  public static final String PATH = "/health";

  private final ApiRequestMatcher apiRequestMatcher;

  @Inject
  public HealthConfig(@NotNull ApiRequestMatcher apiRequestMatcher) {
    this.apiRequestMatcher = apiRequestMatcher;
  }

  /** Health namespace shared by security matching and execution-context exclusion. */
  @Bean
  @Qualifier("executionContextExclusion")
  @NotNull
  public Predicate<HttpServletRequest> healthRequests() {
    var matcher = apiRequestMatcher.forPattern(PATH + "/**");
    return matcher::matches;
  }

  @Bean
  @Order(0)
  @NotNull
  public SecurityFilterChain healthFilterChain(@NotNull HttpSecurity http,
      @Qualifier("healthRequests") @NotNull Predicate<HttpServletRequest> healthRequests)
      throws Exception {
    return http
        .requestMatcher(healthRequests::test)
        .csrf(csrf -> csrf.disable())
        .requestCache(cache -> cache.disable())
        .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        // Check the receiving connector, never Host or forwarding headers.
        .authorizeHttpRequests(authorize -> authorize.anyRequest().access((authentication, context) ->
            new AuthorizationDecision(context.getRequest().getLocalPort() == 9090)))
        .build();
  }
}
