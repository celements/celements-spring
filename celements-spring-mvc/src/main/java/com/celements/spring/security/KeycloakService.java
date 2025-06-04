package com.celements.spring.security;

import java.util.Optional;

import javax.inject.Inject;

import org.xwiki.configuration.ConfigurationSource;

import com.google.common.base.Strings;
import com.xpn.xwiki.XWikiConstant;

public class KeycloakService implements IdentityServer {

  private final ConfigurationSource configSource;

  @Inject
  public KeycloakService(ConfigurationSource configSource) {
    this.configSource = configSource;
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
