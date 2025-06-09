package com.celements.spring.security;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.springframework.security.authentication.AuthenticationManager;
import org.xwiki.model.reference.WikiReference;

public interface IdentityServer {

  @NotEmpty
  String getHost();

  @NotEmpty
  String getRealm();

  @NotEmpty
  String getJwkSetUri();

  @NotNull
  AuthenticationManager getAuthenticationManagerForWiki(WikiReference wikiRef);

}
