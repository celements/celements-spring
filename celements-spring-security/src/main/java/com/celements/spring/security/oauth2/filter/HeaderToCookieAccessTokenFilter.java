package com.celements.spring.security.oauth2.filter;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import com.celements.spring.security.oauth2.cookietoken.CookieTokenService;

public class HeaderToCookieAccessTokenFilter extends OncePerRequestFilter {

  private static final Logger LOGGER = LoggerFactory
      .getLogger(HeaderToCookieAccessTokenFilter.class);

  private final CookieTokenService tokenService;

  public HeaderToCookieAccessTokenFilter(CookieTokenService tokenService) {
    this.tokenService = tokenService;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp,
      FilterChain chain) throws ServletException, IOException {
    syncAccessTokenCookie(req, resp);
    chain.doFilter(req, resp);
  }

  private Optional<String> getHeaderBearer(HttpServletRequest req) {
    return Optional.ofNullable(req.getHeader("Authorization"))
        .filter(header -> header.startsWith("Bearer "))
        .map(header -> header.substring(7));
  }

  /**
   * Only set cookie when:
   * - request had a validated bearer (auth is authenticated),
   * - header was used (Authorization present),
   * - cookie is missing or out-of-sync with the header.
   *
   * @param req
   * @param resp
   */
  private void syncAccessTokenCookie(HttpServletRequest req, HttpServletResponse resp) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    boolean isAuthenticated = (auth instanceof JwtAuthenticationToken) && auth.isAuthenticated();
    Optional<String> bearerOpt = getHeaderBearer(req);
    if (!isAuthenticated || bearerOpt.isEmpty()) {
      LOGGER.debug("no cookie set for header auth={}, bearer-present={}", isAuthenticated,
          bearerOpt.isPresent());
      return;
    }
    if (!bearerOpt.get().equals(tokenService.getAccessToken(req).orElse(null))) {
      // We already trust it (validated by BearerTokenAuthenticationFilter). We just need expiry.
      var jwt = ((JwtAuthenticationToken) auth).getToken();
      LOGGER.info("setting auth-cookie for auth-header exp={}", jwt.getExpiresAt());
      tokenService.storeAccessJwtCookie(resp, jwt.getTokenValue(), jwt.getExpiresAt());
    } else {
      LOGGER.debug("skip setting identical cookie");
    }
  }

}
