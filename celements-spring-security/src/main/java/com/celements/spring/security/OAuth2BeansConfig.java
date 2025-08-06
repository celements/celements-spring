package com.celements.spring.security;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.xwiki.context.Execution;

import com.celements.execution.XWikiExecutionProp;
import com.xpn.xwiki.XWikiConstant;

@Configuration
public class OAuth2BeansConfig {

  private final IdentityService identityService;
  private final Execution excecution;

  @Inject
  public OAuth2BeansConfig(IdentityService identityService, Execution excecution) {
    this.identityService = identityService;
    this.excecution = excecution;
  }

  @Bean
  public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
    // Uses only thread-local ExecutionContext; request is ignored.
    return request -> identityService.getAuthenticationManagerForWiki(
        excecution.getContext().get(XWikiExecutionProp.WIKI)
            .orElse(XWikiConstant.MAIN_WIKI));
  }

  @Bean
  public OAuth2AuthorizedClientService authorizedClientService(
      ClientRegistrationRepository clientRegistrationRepository) {
    return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
  }

}
