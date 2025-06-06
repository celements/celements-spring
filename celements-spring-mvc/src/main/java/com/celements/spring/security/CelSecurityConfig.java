package com.celements.spring.security;

import static com.celements.logging.LogUtils.*;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;

import com.celements.model.context.ModelContext;

@Configuration
@EnableWebSecurity
public class CelSecurityConfig {

  private static final Logger LOGGER = LoggerFactory.getLogger(CelSecurityConfig.class);

  private final IdentityServer identitySrv;
  private final ModelContext context;

  private final Map<String, JwtDecoder> decoderCache = new ConcurrentHashMap<>();

  @Inject
  public CelSecurityConfig(IdentityServer identityServer, ModelContext context) {
    this.identitySrv = identityServer;
    this.context = context;
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

  /**
   * Inspect the HttpServletRequest (e.g. request.getServerName()) and return an
   * AuthenticationManager
   * that knows how to validate the Bearer token for that domain. Internally, it builds (or reuses)
   * a JwtDecoder that points at the Keycloak JWK-Set URI for that domain, then wraps it in a
   * JwtAuthenticationProvider. Finally, it returns a simple ProviderManager that only contains that
   * one provider.
   */
  @Bean
  public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
    return (HttpServletRequest request) -> {
      // Here we pick a "tenant" or "domain" key. You can also look at a custom header if needed.
      String domain = request.getServerName();
      LOGGER.info("Resolving AuthenticationManager for domain: {} and database={}", domain,
          context.getXWikiContext().getDatabase());

      // Look up (or build and cache) the JwtDecoder for this domain
      JwtDecoder jwtDecoder = decoderCache.computeIfAbsent(domain, this::buildJwtDecoderForDomain);

      // Create a JwtAuthenticationProvider that uses this decoder + our converter
      JwtAuthenticationProvider provider = new JwtAuthenticationProvider(jwtDecoder);
      provider.setJwtAuthenticationConverter(jwtAuthConverter());

      // Wrap it in a ProviderManager (which implements AuthenticationManager)
      return new ProviderManager(provider);
    };
  }

  /**
   * Build a NimbusJwtDecoder for the given domain. You decide how to map "domain" → Keycloak
   * host/realm.
   */
  private JwtDecoder buildJwtDecoderForDomain(String domain) {
    // Here we delegate to your existing IdentityServer logic, but passing the domain
    // You might look up a map of domain → (host, realm), or change identitySrv so that
    // it reacts to a "current domain" context. For demonstration, assume identitySrv
    // uses the domain internally to pick the correct host & realm.
    String host = identitySrv.getHost();
    String realm = identitySrv.getRealm();
    LOGGER.info("Building JwtDecoder for domain={}, host={}, realm={}", domain, host, realm);

    String jwkSetUri = "https://" + host + "/auth/realms/" + realm
        + "/protocol/openid-connect/certs";
    return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
  }

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
