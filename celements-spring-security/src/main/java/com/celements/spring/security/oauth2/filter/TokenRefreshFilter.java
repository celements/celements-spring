package com.celements.spring.security.oauth2.filter;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import com.celements.spring.security.oauth2.cookietoken.CookieTokenService;
import com.celements.spring.security.oauth2.cookietoken.CookieTokenService.RefreshedTokens;

public class TokenRefreshFilter extends OncePerRequestFilter {

  private final CookieTokenService tokenService;
  private final AuthenticationEntryPoint entryPoint;
  private final DefaultBearerTokenResolver headerResolver = new DefaultBearerTokenResolver();

  public TokenRefreshFilter(CookieTokenService cookieService, AuthenticationEntryPoint entryPoint) {
    this.tokenService = cookieService;
    this.entryPoint = entryPoint;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    try {
      return headerResolver.resolve(request) != null;
    } catch (OAuth2AuthenticationException exp) {
      // Let bearer authentication reject malformed headers without refreshing cookies.
      return true;
    }
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp,
      FilterChain chain) throws ServletException, IOException {
    Optional<RefreshedTokens> refreshedTokens;
    try {
      refreshedTokens = tokenService.refreshTokens(req);
    } catch (OAuth2AuthorizationException exp) {
      if (!OAuth2ErrorCodes.INVALID_GRANT.equals(exp.getError().getErrorCode())) {
        throw exp;
      }
      entryPoint.commence(req, resp, new BadCredentialsException("Refresh token rejected"));
      return;
    }
    refreshedTokens.ifPresent(tokens -> {
      tokenService.storeTokens(resp, tokens.accessToken(), tokens.refreshToken());
      req.setAttribute(CookieTokenService.REFRESHED_ACCESS_TOKEN_ATTRIBUTE,
          tokens.accessToken().getTokenValue());
    });
    chain.doFilter(req, resp);
  }
}
