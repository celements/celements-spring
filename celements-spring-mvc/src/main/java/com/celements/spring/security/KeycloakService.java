package com.celements.spring.security;

import java.util.Optional;

import javax.inject.Inject;
import javax.inject.Named;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.xwiki.configuration.ConfigurationSource;

import com.celements.configuration.CelementsAllConfigurationSource;
import com.google.common.base.Strings;
import com.xpn.xwiki.XWikiConstant;

@Component
public class KeycloakService implements IdentityServer {

  private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakService.class);

  private final ConfigurationSource configSource;

  @Inject
  public KeycloakService(
      @Named(CelementsAllConfigurationSource.NAME) ConfigurationSource configSource) {
    this.configSource = configSource;
    LOGGER.info("KeycloakService constructor: {} host={}, realm={}", configSource.getClass(),
        getHost(), getRealm());
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
        .orElse(XWikiConstant.MAIN_WIKI.getName());
  }

}
