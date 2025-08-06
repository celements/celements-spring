package com.celements.spring.security;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.web.util.WebUtils;

@Service
public class OAuth2CookieService {

  private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2CookieService.class);

  public static final String COOKIE_ACCESS_TOKEN = "access_token";
  public static final String COOKIE_REFRESH_TOKEN = "refresh_token";

  private final WikiClientRegistrationRepository registrationRepo;
  private final IdentityService identityService;
  private final OAuth2AuthorizedClientManager authorizedClientManager;

  public OAuth2CookieService(
      WikiClientRegistrationRepository registrationRepo,
      IdentityService identityService,
      OAuth2AuthorizedClientManager authorizedClientManager) {
    this.registrationRepo = registrationRepo;
    this.identityService = identityService;
    this.authorizedClientManager = authorizedClientManager;
  }

  public void storeTokensInCookies(HttpServletResponse response, OAuth2AuthorizedClient client) {
    OAuth2AccessToken accessToken = client.getAccessToken();
    OAuth2RefreshToken refreshToken = client.getRefreshToken();
    // Set as HttpOnly cookies
    setTokenCookie(response, COOKIE_ACCESS_TOKEN, accessToken.getTokenValue(),
        accessToken.getExpiresAt());
    if (refreshToken != null) {
      setTokenCookie(response, COOKIE_REFRESH_TOKEN, refreshToken.getTokenValue(),
          refreshToken.getExpiresAt());
    }
  }

  public Optional<OAuth2AuthorizedClient> refreshTokens(HttpServletRequest req) {
    Optional<OAuth2AuthorizedClient> oldClientOpt = reconstructAuthClientFromCookie(req);
    return oldClientOpt
        .map(existingClient -> OAuth2AuthorizeRequest
            .withClientRegistrationId(identityService.getRegistrationId())
            .principal(existingClient.getPrincipalName())
            // here's where you hand Spring your pre‐built client:
            .attribute(OAuth2AuthorizedClient.class.getName(), existingClient)
            .build())
        .map(authorizedClientManager::authorize)
        .filter(client -> !client.getAccessToken().getTokenValue()
            .equals(oldClientOpt.get().getAccessToken().getTokenValue())
            || ((client.getRefreshToken() != null) && !client.getRefreshToken().getTokenValue()
                .equals(oldClientOpt.get().getRefreshToken().getTokenValue())));
  }

  public Optional<OAuth2AuthorizedClient> reconstructAuthClientFromCookie(HttpServletRequest req) {
    try {
      Optional<Jwt> accessJwtOpt = getJwtFromCookie(req, COOKIE_ACCESS_TOKEN);
      Optional<OAuth2RefreshToken> refreshTokenOpt = getRefreshTokenFromCookie(req);
      if (accessJwtOpt.isPresent() && refreshTokenOpt.isPresent()) {
        OAuth2AccessToken accessToken = reconstructAccessTokenFromJwt(accessJwtOpt.get());
        OAuth2RefreshToken refreshToken = refreshTokenOpt.get();
        return Optional.of(new OAuth2AuthorizedClient(
            registrationRepo.findByRegistrationId(identityService.getRegistrationId()),
            accessJwtOpt.get().getSubject(),
            accessToken,
            refreshToken));
      }
    } catch (OAuth2AuthenticationException exp) {
      LOGGER.info("No valid access token found", exp);
    }
    return Optional.empty();
  }

  /**
   * @param request
   *          the request
   * @return the Refresh Token or optional.empty if none found
   * @throws OAuth2AuthenticationException
   *           if the found token is invalid
   */
  public Optional<OAuth2RefreshToken> getRefreshTokenFromCookie(HttpServletRequest req) {
    return getJwtFromCookie(req, COOKIE_REFRESH_TOKEN)
        .map(refreshToken -> new OAuth2RefreshToken(
            refreshToken.getTokenValue(),
            refreshToken.getIssuedAt()));
  }

  /**
   * Resolve any
   * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
   * Token</a> value from the access_token cookie in the request.
   *
   * @param request
   *          the request
   * @return the Bearer Access Token or optional.empty if none found
   * @throws OAuth2AuthenticationException
   *           if the found token is invalid
   */
  public Optional<OAuth2AccessToken> getAccessTokenFromCookie(HttpServletRequest req) {
    return getJwtFromCookie(req, COOKIE_ACCESS_TOKEN)
        .map(this::reconstructAccessTokenFromJwt);
  }

  private OAuth2AccessToken reconstructAccessTokenFromJwt(Jwt accessToken) {
    return new OAuth2AccessToken(
        OAuth2AccessToken.TokenType.BEARER,
        accessToken.getTokenValue(),
        accessToken.getIssuedAt(),
        accessToken.getExpiresAt(),
        getScopesFromJwt(accessToken));
  }

  public void setTokenCookie(HttpServletResponse response, String name, String value,
      java.time.Instant expiry) {
    Cookie cookie = new Cookie(name, value);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath("/");
    if (expiry != null) {
      long maxAge = (expiry.getEpochSecond() - java.time.Instant.now().getEpochSecond());
      cookie.setMaxAge((int) maxAge);
    }
    response.addCookie(cookie);
  }

  private Optional<Jwt> getJwtFromCookie(HttpServletRequest req, String cookieName) {
    try {
      return Optional.ofNullable(WebUtils.getCookie(req, cookieName))
          .map(cookie -> identityService.getJwtDecoder().decode(cookie.getValue()));
    } catch (JwtException exp) {
      LOGGER.debug("Failed to decode token from cookie '{}' ", cookieName, exp);
      throw new OAuth2AuthenticationException(exp.getMessage());
    }
  }

  private Set<String> getScopesFromJwt(Jwt jwt) {
    List<String> scopes = jwt.getClaimAsStringList("scope");
    // sometimes Keycloak uses "scp" instead:
    if (scopes == null) {
      scopes = jwt.getClaimAsStringList("scp");
    }
    return new HashSet<>(scopes);
  }
}
