package com.celements.spring.security.oauth2.auth;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.validation.constraints.NotEmpty;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.stereotype.Component;

import com.celements.spring.security.oauth2.IdentityService;

@Component
public class WikiClientRegistrationRepository implements ClientRegistrationRepository {

  private static final Logger LOGGER = LoggerFactory
      .getLogger(WikiClientRegistrationRepository.class);

  private final IdentityService identityService;

  @Inject
  public WikiClientRegistrationRepository(IdentityService identityService) {
    this.identityService = identityService;
  }

  @Override
  @Nullable
  public ClientRegistration findByRegistrationId(@NotEmpty String registrationId) {
    LOGGER.debug("findByRegistrationId for {}", registrationId);
    if (!isValidRegistrationId(registrationId)) {
      return null;
    }

    Map<String, Object> providerMetadata = new HashMap<>();
    providerMetadata.put("end_session_endpoint", identityService.getOAuth2BaseUrl() + "logout");

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
        .providerConfigurationMetadata(providerMetadata)
        .build();
  }

  private boolean isValidRegistrationId(String registrationId) {
    return registrationId.equals(identityService.getRegistrationId());
  }
}
