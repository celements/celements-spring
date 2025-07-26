package com.celements.spring.security;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.springframework.security.authentication.AuthenticationManager;
import org.xwiki.model.reference.WikiReference;

public interface IdentityService {

  @NotEmpty
  String getHost();

  @NotEmpty
  String getRealm();

  @NotEmpty
  String getLoginClientId();

  @NotEmpty
  String getLoginClientSecret();

  @NotEmpty
  String getJwkSetUri();

  @NotNull
  AuthenticationManager getAuthenticationManagerForWiki(WikiReference wikiRef);

  @NotEmpty
  String getOAuth2BaseUrl();

  @NotEmpty
  String getIssuerUri();

  @NotEmpty
  String getLoginUrl();

  @NotEmpty
  String getRegistrationId();

  @NotEmpty
  String getLogoutSucessUrl();

}
