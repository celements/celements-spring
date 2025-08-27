package com.celements.spring.security.web.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import com.celements.spring.security.web.OAuth2CookieService;

public class TokenRefreshFilter extends OncePerRequestFilter {

  private final OAuth2CookieService cookieService;

  public TokenRefreshFilter(OAuth2CookieService cookieService) {
    this.cookieService = cookieService;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req,
      HttpServletResponse resp, FilterChain chain)
      throws ServletException, IOException {
    cookieService.refreshTokens(req)
        .ifPresent(refreshedClient -> cookieService.storeTokensInCookies(resp, refreshedClient));
    chain.doFilter(req, resp);
  }
}
