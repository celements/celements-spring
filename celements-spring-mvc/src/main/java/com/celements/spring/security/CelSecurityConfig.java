package com.celements.spring.security;

import static com.celements.logging.LogUtils.*;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class CelSecurityConfig {

  private static final Logger LOGGER = LoggerFactory.getLogger(CelSecurityConfig.class);

  private final IdentityServer identitySrv;

  @Inject
  public CelSecurityConfig(IdentityServer identityServer) {
    this.identitySrv = identityServer;
  }

  // 1) Define your SecurityFilterChain bean
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    LOGGER.info("securityFilterChain called for {}, {}", defer(identitySrv::getHost),
        defer(identitySrv::getRealm));
    http
        // disable CSRF for stateless REST APIs
        .csrf().disable()
        // stateless session management
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        // URL authorization rules
        .authorizeHttpRequests(authorize -> authorize
            .antMatchers("/api/public/**").permitAll()
            .anyRequest().authenticated())
        // configure JWT-based OAuth2 Resource Server support
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .jwtAuthenticationConverter(jwtAuthConverter())))
        // (5) Make sure missing token → 401 (instead of falling through to your controller):
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
            .accessDeniedHandler(new BearerTokenAccessDeniedHandler()));
    return http.build();
  }

  // 3) Point Spring Security at Keycloak’s JWKS endpoint
  @Bean
  public JwtDecoder jwtDecoder() {
    LOGGER.info("jwtDecoder called for {}, {}", defer(identitySrv::getHost),
        defer(identitySrv::getRealm));
    String jwkSetUri = "https://" + identitySrv.getHost() + "/auth/realms/" + identitySrv.getRealm()
        + "/protocol/openid-connect/certs";
    return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
  }

  // 2) (Optional) If there are static resources or swagger UI you truly want Spring Security to
  // ignore:
  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (web) -> web
        .ignoring()
        .antMatchers("/favicon.ico", "/api/v3/api-docs");
  }

  // 4) Map Keycloak realm roles into Spring authorities
  private JwtAuthenticationConverter jwtAuthConverter() {
    JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
    authoritiesConverter.setAuthoritiesClaimName("realm_access.roles");
    authoritiesConverter.setAuthorityPrefix("ROLE_");

    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
    return converter;
  }
}
