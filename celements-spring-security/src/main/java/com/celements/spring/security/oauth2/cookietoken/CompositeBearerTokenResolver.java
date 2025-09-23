package com.celements.spring.security.oauth2.cookietoken;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

public class CompositeBearerTokenResolver implements BearerTokenResolver {

  private final BearerTokenResolver header = new DefaultBearerTokenResolver();
  private final BearerTokenResolver cookie;

  public CompositeBearerTokenResolver(BearerTokenResolver cookie) {
    this.cookie = cookie;
  }

  @Override
  public String resolve(HttpServletRequest request) {
    String fromCookie = cookie.resolve(request);
    String fromHeader = header.resolve(request);

    if ((fromCookie != null) && (fromHeader != null) && !fromCookie.equals(fromHeader)) {
      BearerTokenError error = BearerTokenErrors
          .invalidRequest("Found multiple bearer tokens in the request");
      throw new OAuth2AuthenticationException(error);
    }
    return (fromCookie != null) ? fromCookie : fromHeader;
  }
}
