package com.celements.spring.security;

import org.springframework.stereotype.Component;
import org.xwiki.script.service.ScriptService;

@Component("identity")
public class IdentityServerScriptService implements ScriptService {

  private IdentityServer identityServer;

  public IdentityServerScriptService(IdentityServer identityServer) {
    this.identityServer = identityServer;
  }

  public String getHost() {
    return this.identityServer.getHost();
  }

  public String getRealm() {
    return this.identityServer.getRealm();
  }

}
