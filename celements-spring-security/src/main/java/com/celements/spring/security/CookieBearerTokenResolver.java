package com.celements.spring.security;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;

public class CookieBearerTokenResolver implements BearerTokenResolver {

  private static final Logger LOGGER = LoggerFactory.getLogger(CookieBearerTokenResolver.class);

  private final OAuth2CookieService cookieService;

  public CookieBearerTokenResolver(OAuth2CookieService cookieService) {
    this.cookieService = cookieService;
  }

  @Override
  public String resolve(HttpServletRequest req) {
    try {
      return cookieService.getAccessTokenFromCookie(req)
          .map(t -> t.getTokenValue())
          .orElse(null);
    } catch (OAuth2AuthenticationException exp) {
      LOGGER.info("No valid access token found", exp);
    }
    return null;
  }
}
