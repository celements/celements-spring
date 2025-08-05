package com.celements.spring.security;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;

public class CookieBearerTokenResolver implements BearerTokenResolver {

  private final OAuth2CookieService cookieService;

  public CookieBearerTokenResolver(OAuth2CookieService cookieService) {
    this.cookieService = cookieService;
  }

  @Override
  public String resolve(HttpServletRequest req) {
    return cookieService.getAccessTokenFromCookie(req)
        .map(t -> t.getTokenValue())
        .orElse(null);
  }
}
