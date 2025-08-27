package com.celements.spring.security.oauth2.wiki;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import com.celements.spring.security.oauth2.cookietoken.CookieTokenService;

public class CelAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  private final OAuth2AuthorizedClientService clientService;
  private final CookieTokenService tokenService;

  public CelAuthenticationSuccessHandler(OAuth2AuthorizedClientService clientService,
      CookieTokenService cookieService) {
    this.clientService = clientService;
    this.tokenService = cookieService;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    if (authentication instanceof OAuth2AuthenticationToken) {
      OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
      OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(
          oauthToken.getAuthorizedClientRegistrationId(),
          oauthToken.getName());
      if (client != null) {
        tokenService.storeTokens(response, client);
      }
    }
    var saved = new SavedRequestAwareAuthenticationSuccessHandler();
    saved.setDefaultTargetUrl("/");
    saved.onAuthenticationSuccess(request, response, authentication);
  }

}
