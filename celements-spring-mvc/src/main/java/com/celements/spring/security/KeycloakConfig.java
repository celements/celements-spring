package com.celements.spring.security;

import static com.celements.logging.LogUtils.*;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class KeycloakConfig {

  private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakConfig.class);

  private final IdentityServer identitySrv;

  @Inject
  public KeycloakConfig(IdentityServer identityServer) {
    this.identitySrv = identityServer;
  }

  @Bean
  public JwtDecoder jwtDecoder() {
    LOGGER.info("jwtDecoder called for {}, {}", defer(identitySrv::getHost),
        defer(identitySrv::getRealm));
    String jwkSetUri = "https://" + identitySrv.getHost() + "/auth/realms/" + identitySrv.getRealm()
        + "/protocol/openid-connect/certs";
    return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
  }

}
