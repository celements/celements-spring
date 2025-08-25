package com.celements.spring.security;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class OAuth2CookieAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  private final OAuth2AuthorizedClientService clientService;
  private final OAuth2CookieService cookieService;

  public OAuth2CookieAuthenticationSuccessHandler(OAuth2AuthorizedClientService clientService,
      OAuth2CookieService cookieService) {
    this.clientService = clientService;
    this.cookieService = cookieService;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException {
    if (authentication instanceof OAuth2AuthenticationToken) {
      OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
      OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(
          oauthToken.getAuthorizedClientRegistrationId(),
          oauthToken.getName());
      if (client != null) {
        cookieService.storeTokensInCookies(response, client);
      }
    }
    // TODO Redirect to original URL
    // TODO fallback wiki-login-URL
    response.sendRedirect("/");
  }

}
