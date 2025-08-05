package com.celements.spring.security;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.web.util.WebUtils;

public class CookieBearerTokenResolver implements BearerTokenResolver {

  private final String cookieName;

  public CookieBearerTokenResolver(String cookieName) {
    this.cookieName = cookieName;
  }

  @Override
  public String resolve(HttpServletRequest req) {
    Cookie c = WebUtils.getCookie(req, cookieName);
    return c != null ? c.getValue() : null;
  }
}
