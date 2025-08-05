package com.celements.spring.security;

import java.io.IOException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class OAuth2CookieAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  private final OAuth2AuthorizedClientService clientService;

  public OAuth2CookieAuthenticationSuccessHandler(OAuth2AuthorizedClientService clientService) {
    this.clientService = clientService;
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
        OAuth2AccessToken accessToken = client.getAccessToken();
        OAuth2RefreshToken refreshToken = client.getRefreshToken();
        // Set as HttpOnly cookies
        setTokenCookie(response, "access_token", accessToken.getTokenValue(),
            accessToken.getExpiresAt());
        if (refreshToken != null) {
          setTokenCookie(response, "refresh_token", refreshToken.getTokenValue(),
              refreshToken.getExpiresAt());
        }
      }
    }
    // Redirect to original URL
    response.sendRedirect("/");
  }

  private void setTokenCookie(HttpServletResponse response, String name, String value,
      java.time.Instant expiry) {
    Cookie cookie = new Cookie(name, value);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath("/");
    if (expiry != null) {
      long maxAge = (expiry.getEpochSecond() - java.time.Instant.now().getEpochSecond());
      cookie.setMaxAge((int) maxAge);
    }
    response.addCookie(cookie);
  }
}
