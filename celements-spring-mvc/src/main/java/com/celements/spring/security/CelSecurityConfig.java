package com.celements.spring.security;

import static com.celements.logging.LogUtils.*;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.xwiki.context.Execution;

import com.celements.execution.XWikiExecutionProp;
import com.xpn.xwiki.XWikiConstant;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(jsr250Enabled = true, prePostEnabled = true)
public class CelSecurityConfig {

  private static final Logger LOGGER = LoggerFactory.getLogger(CelSecurityConfig.class);

  private final IdentityService identityService;
  private final Execution excecution;

  @Inject
  public CelSecurityConfig(IdentityService identityService, Execution excecution) {
    this.identityService = identityService;
    this.excecution = excecution;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    LOGGER.info("securityFilterChain called for {}, {}", defer(identityService::getHost),
        defer(identityService::getRealm));
    return http
        .csrf().disable()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
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
