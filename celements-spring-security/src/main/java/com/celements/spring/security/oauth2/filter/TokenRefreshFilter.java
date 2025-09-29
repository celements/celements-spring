package com.celements.spring.security.oauth2.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import com.celements.spring.security.oauth2.cookietoken.CookieTokenService;

public class TokenRefreshFilter extends OncePerRequestFilter {

  private final CookieTokenService tokenService;

  public TokenRefreshFilter(CookieTokenService cookieService) {
    this.tokenService = cookieService;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp,
      FilterChain chain) throws ServletException, IOException {
    tokenService.refreshTokens(req, resp)
        .ifPresent(refreshedClient -> tokenService.storeTokens(resp, refreshedClient));
    chain.doFilter(req, resp);
  }
}
