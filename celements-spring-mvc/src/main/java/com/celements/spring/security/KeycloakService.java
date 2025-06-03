package com.celements.spring.security;

import static com.celements.logging.LogUtils.*;

import java.util.Optional;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.xwiki.configuration.ConfigurationSource;

import com.celements.model.context.ModelContext;
import com.google.common.base.Strings;

@Component
public class KeycloakService implements IdentityServer {

  private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakService.class);

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
  public String getHost() {
    return Optional
        .ofNullable(Strings.emptyToNull(configSource.getProperty("celements.keykloak.host")))
        .orElse("localhost");
  }

  @Override
  public String getRealm() {
    return Optional
        .ofNullable(Strings.emptyToNull(configSource.getProperty("celements.keykloak.realm")))
        .orElse(context.getWikiRef().getName());
  }

  @Bean
  public JwtDecoder jwtDecoder() {
    LOGGER.info("jwtDecoder called for {}, {}", defer(() -> getHost()), defer(() -> getRealm()));
    String jwkSetUri = "https://" + getHost() + "/auth/realms/" + getRealm()
        + "/protocol/openid-connect/certs";
    return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
  }

}
