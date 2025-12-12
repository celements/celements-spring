package com.celements.spring.security.oauth2.cookietoken;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;

public class CookieBearerTokenResolver implements BearerTokenResolver {

  private static final Logger LOGGER = LoggerFactory.getLogger(CookieBearerTokenResolver.class);

  private final CookieTokenService tokenService;

  public CookieBearerTokenResolver(CookieTokenService tokenService) {
    this.tokenService = tokenService;
  }

  @Override
  public String resolve(HttpServletRequest req) {
    try {
      return tokenService.getAccessToken(req).orElse(null);
    } catch (OAuth2AuthenticationException exp) {
      LOGGER.info("No valid access token found", exp);
    }
    return null;
  }
}
