package com.celements.spring.security.oauth2;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.xwiki.context.Execution;

import com.celements.execution.XWikiExecutionProp;
import com.xpn.xwiki.XWikiConstant;

@Configuration
public class OAuth2Config {

  private final IdentityService identityService;
  private final Execution execution;

  @Inject
  public OAuth2Config(IdentityService identityService, Execution excecution) {
    this.identityService = identityService;
    this.execution = excecution;
  }

  @Bean
  @NotNull
  public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
    // Uses only thread-local ExecutionContext; request is ignored.
    return request -> identityService.getAuthenticationManagerForWiki(
        execution.getContext().get(XWikiExecutionProp.WIKI)
            .orElse(XWikiConstant.MAIN_WIKI));
  }

  @Bean
  @NotNull
  public OAuth2AuthorizedClientService authorizedClientService(
      @NotNull ClientRegistrationRepository clientRegistrationRepository) {
    return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
  }

  @Bean
  @NotNull
  public OAuth2AuthorizedClientRepository authorizedClientRepository(
      @NotNull OAuth2AuthorizedClientService clientService) {
    return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(clientService);
  }

  @Bean
  @NotNull
  public OAuth2AuthorizedClientManager authorizedClientManager(
      @NotNull ClientRegistrationRepository clientRegistrations,
      @NotNull OAuth2AuthorizedClientRepository authorizedClients) {
    // 1) build the provider that knows how to handle code & refresh flows
    OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder()
        .authorizationCode()
        .refreshToken()
        .build();
    // 2) wire it into the default manager
    DefaultOAuth2AuthorizedClientManager manager = new DefaultOAuth2AuthorizedClientManager(
        clientRegistrations, authorizedClients);
    manager.setAuthorizedClientProvider(provider);
    return manager;
  }

}
