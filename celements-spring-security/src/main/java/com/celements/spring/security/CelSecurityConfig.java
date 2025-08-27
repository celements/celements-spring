package com.celements.spring.security;

import static com.celements.logging.LogUtils.*;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.xwiki.context.Execution;

import com.celements.auth.user.UserService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled = true, prePostEnabled = true)
public class CelSecurityConfig {

  private static final Logger LOGGER = LoggerFactory.getLogger(CelSecurityConfig.class);

  private final IdentityService identityService;
  private final OAuth2AuthorizedClientService authorizedClientService;
  private final OAuth2CookieService cookieService;
  private final AuthenticationManagerResolver<HttpServletRequest> authManagerResolver;
  private final UserService userService;
  private final OAuth2TenantRequestMatcher oAuthTenantMatcher;
  private final Execution execution;

  @Inject
  public CelSecurityConfig(
      IdentityService identityService,
      OAuth2AuthorizedClientService authorizedClientService, 
      OAuth2CookieService cookieService,
      AuthenticationManagerResolver<HttpServletRequest> authManagerResolver,
      UserService userService,
      OAuth2TenantRequestMatcher oAuthTenantMatcher, 
      Execution execution) {
    this.identityService = identityService;
    this.authorizedClientService = authorizedClientService;
    this.cookieService = cookieService;
    this.authManagerResolver = authManagerResolver;
    this.userService = userService;
    this.oAuthTenantMatcher = oAuthTenantMatcher;
    this.execution = execution;
  }

  @Bean
  @Order(1)
  public SecurityFilterChain loginFilterChain(HttpSecurity http) throws Exception {
    LOGGER.info("loginFilterChain called for {}, {}, {}", defer(identityService::getHost),
        defer(identityService::getRealm), defer(identityService::getLoginUrl));
    return http
        // only non-API paths for tenants with OAuth
        .requestMatcher(new AndRequestMatcher(
            new NegatedRequestMatcher(new AntPathRequestMatcher("/api/**")),
            oAuthTenantMatcher))
        .csrf(csrf -> csrf.disable())
        .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
        .oauth2Login(oauth2 -> oauth2.loginPage("/oauth2/authorization/{registrationId}")
            .successHandler(new OAuth2CookieAuthenticationSuccessHandler(authorizedClientService,
                cookieService)))
        .oauth2ResourceServer(rs -> rs
            .bearerTokenResolver(new CookieBearerTokenResolver(cookieService))
            .authenticationManagerResolver(authManagerResolver))
        .addFilterBefore(
            new TokenRefreshFilter(cookieService),
            BearerTokenAuthenticationFilter.class)
        .addFilterAfter(
            new ExecutionContextAuthenticationFilter(userService, execution),
            BearerTokenAuthenticationFilter.class)
        .exceptionHandling(ex -> ex
            .authenticationEntryPoint(new WikiAuthenticationEntryPoint(identityService)))
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
    LOGGER.info("apiFilterChain called for {}, {}", defer(identityService::getHost),
        defer(identityService::getRealm));
    return http
        .requestMatchers(r -> r.antMatchers("/api/**"))
        .csrf().disable()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeHttpRequests(authorize -> authorize
            .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
            .anyRequest().permitAll())
        .oauth2ResourceServer(oauth2 -> oauth2
            .authenticationManagerResolver(authManagerResolver))
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
            .accessDeniedHandler(new BearerTokenAccessDeniedHandler()))
        .build();
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return web -> web
        .ignoring()
        .antMatchers("/favicon.ico", "/api/v3/api-docs");
  }

}
