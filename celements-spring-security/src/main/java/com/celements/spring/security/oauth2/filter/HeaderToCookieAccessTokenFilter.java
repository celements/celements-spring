package com.celements.spring.security.oauth2.filter;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import com.celements.spring.security.oauth2.cookietoken.CookieTokenService;

public class HeaderToCookieAccessTokenFilter extends OncePerRequestFilter {

  private final CookieTokenService tokenService;

  public HeaderToCookieAccessTokenFilter(CookieTokenService tokenService) {
    this.tokenService = tokenService;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp,
      FilterChain chain) throws ServletException, IOException {
    // Only set when:
    // - request had a validated bearer (auth is authenticated),
    // - header was used (Authorization present),
    // - cookie is missing or out-of-sync with the header.
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Optional<String> bearer = getHeaderBearer(req);
    if ((auth instanceof JwtAuthenticationToken) && auth.isAuthenticated() && bearer.isPresent()) {
      String cookieVal = tokenService.getAccessToken(req).orElse(null);
      if (!bearer.get().equals(cookieVal)) {
        // We already trust it (validated by BearerTokenAuthenticationFilter). We just need expiry.
        var jwt = ((JwtAuthenticationToken) auth).getToken();
        tokenService.storeAccessJwtCookie(resp, jwt.getTokenValue(), jwt.getExpiresAt());
      }
    }
    chain.doFilter(req, resp);
  }

  private Optional<String> getHeaderBearer(HttpServletRequest req) {
    return Optional.ofNullable(req.getHeader("Authorization"))
        .filter(header -> header.startsWith("Bearer "))
        .map(header -> header.substring(7));
  }
}
