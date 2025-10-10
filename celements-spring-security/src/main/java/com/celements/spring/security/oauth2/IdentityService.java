package com.celements.spring.security.oauth2;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.xwiki.model.reference.WikiReference;

public interface IdentityService {

  boolean isConfigValid();

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
  String getRevokeUrl();

  @NotEmpty
  String getLoginUrl();

  @NotEmpty
  String getLogoutUrl();

  @NotEmpty
  String getRegistrationId();

  @NotEmpty
  String getLogoutSucessUrl();

  @NotNull
  JwtDecoder getJwtDecoder();

}
