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
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.xwiki.context.Execution;

import com.celements.execution.XWikiExecutionProp;
import com.xpn.xwiki.XWikiConstant;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled = true, prePostEnabled = true)
public class CelSecurityConfig {

  private static final Logger LOGGER = LoggerFactory.getLogger(CelSecurityConfig.class);

  private final IdentityService identityService;
  private final OAuth2AuthorizedClientService authorizedClientService;
  private final Execution excecution;

  @Inject
  public CelSecurityConfig(IdentityService identityService,
      OAuth2AuthorizedClientService authorizedClientService, Execution excecution) {
    this.identityService = identityService;
    this.excecution = excecution;
    this.authorizedClientService = authorizedClientService;
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
            new OAuthTenantRequestMatcher(identityService)))
        .csrf(csrf -> csrf.disable())
        .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
        .oauth2Login(oauth2 -> oauth2.loginPage("/oauth2/authorization/{registrationId}")
            .successHandler(new OAuth2CookieAuthenticationSuccessHandler(authorizedClientService)))
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
            .authenticationManagerResolver(authenticationManagerResolver()))
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
            .accessDeniedHandler(new BearerTokenAccessDeniedHandler()))
        .build();
  }

  @Bean
  public OAuth2AuthorizedClientService authorizedClientService(
      ClientRegistrationRepository clientRegistrationRepository) {
    return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
  }

  @Bean
  public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
    // Uses only thread-local ExecutionContext; request is ignored.
    return request -> identityService.getAuthenticationManagerForWiki(
        excecution.getContext().get(XWikiExecutionProp.WIKI)
            .orElse(XWikiConstant.MAIN_WIKI));
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return web -> web
        .ignoring()
        .antMatchers("/favicon.ico", "/api/v3/api-docs");
  }

}
