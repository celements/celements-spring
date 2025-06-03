package com.celements.spring.security;

import java.util.Optional;

import javax.inject.Inject;

import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.xwiki.configuration.ConfigurationSource;

import com.celements.model.context.ModelContext;
import com.google.common.base.Strings;

@Component
public class KeycloakService implements IdentityServer {

  private final ConfigurationSource configSource;
  private final ModelContext context;

  @Inject
  public KeycloakService(
      ConfigurationSource configSource,
      ModelContext context) {
    this.configSource = configSource;
    this.context = context;
  }

  @Override
  public Optional<String> getHost() {
    return Optional
        .ofNullable(Strings.emptyToNull(configSource.getProperty("celements.keykloak.host")));
  }

  @Override
  public String getRealm() {
    return Optional
        .ofNullable(Strings.emptyToNull(configSource.getProperty("celements.keykloak.realm")))
        .orElse(context.getWikiRef().getName());
  }

  @Bean
  public JwtDecoder jwtDecoder() {
    String jwkSetUri = "https://" + getHost().orElseThrow()
        + "/auth/realms/" + getRealm()
        + "/protocol/openid-connect/certs";
    return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
  }

}
