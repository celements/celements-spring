package com.celements.spring.security;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.util.matcher.RequestMatcher;

public class OAuthTenantRequestMatcher implements RequestMatcher {

  private final IdentityService identityService;

  public OAuthTenantRequestMatcher(IdentityService identityService) {
    this.identityService = identityService;
  }

  @Override
  public boolean matches(HttpServletRequest request) {
    return identityService.isOAuthEnabled();
  }
}
