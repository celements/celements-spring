package com.celements.spring.security;

import javax.inject.Inject;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.stereotype.Component;

@Component
public class WikiClientRegistrationRepository implements ClientRegistrationRepository {

  private final IdentityService identityService;

  @Inject
  public WikiClientRegistrationRepository(IdentityService identityService) {
    this.identityService = identityService;
  }

  @Override
  public ClientRegistration findByRegistrationId(String registrationId) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId(identityService.getLoginClientId())
        .clientSecret(identityService.getLoginClientSecret())
        .issuerUri(identityService.getIssuerUri())
        .scope("openid", "profile", "email")
        .authorizationUri(identityService.getOAuth2BaseUrl() + "auth")
        .tokenUri(identityService.getOAuth2BaseUrl() + "token")
        .jwkSetUri(identityService.getOAuth2BaseUrl() + "certs")
        .userInfoUri(identityService.getOAuth2BaseUrl() + "userinfo")
        .userNameAttributeName(IdTokenClaimNames.SUB)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .build();
  }
}
