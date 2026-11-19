package com.celements.spring.security.oauth2.cookietoken;

import static com.celements.logging.LogUtils.*;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Stream;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.WebUtils;

import com.celements.spring.security.oauth2.IdentityService;
import com.celements.spring.security.oauth2.auth.WikiClientRegistrationRepository;
import com.google.common.base.Strings;

@Service
public class CookieTokenService {

  private static final Logger LOGGER = LoggerFactory.getLogger(CookieTokenService.class);

  public static final String COOKIE_ACCESS_TOKEN = "access_token";
  public static final String COOKIE_REFRESH_TOKEN = "refresh_token";
  public static final String REFRESHED_ACCESS_TOKEN_ATTRIBUTE = CookieTokenService.class.getName()
      + ".refreshedAccessToken";

  private static final DateTimeFormatter PATTERN_FMT = DateTimeFormatter
      .ofPattern("yyyy-MM-dd HH:mm:ss z")
      .withZone(ZoneId.systemDefault());

  private static final Duration REFRESH_SKEW = Duration.ofMinutes(2);

  private final DefaultRefreshTokenTokenResponseClient refreshClient =
      new DefaultRefreshTokenTokenResponseClient();
  private final WikiClientRegistrationRepository registrationRepo;
  private final IdentityService identityService;

  @Inject
  public CookieTokenService(
      WikiClientRegistrationRepository registrationRepo,
      IdentityService identityService) {
    this.registrationRepo = registrationRepo;
    this.identityService = identityService;
  }

  private Optional<String> getTokenValue(@NotNull HttpServletRequest req,
      @NotEmpty String cookieName) {
    return Optional.ofNullable(WebUtils.getCookie(req, cookieName))
        .map(Cookie::getValue)
        .filter(Predicate.not(Strings::isNullOrEmpty));
  }

  public void storeAccessJwtCookie(@NotNull HttpServletResponse response,
      @NotNull String tokenValue, @Nullable Instant expiresAt) {
    setTokenCookie(response, COOKIE_ACCESS_TOKEN, tokenValue, expiresAt);
  }

  public void storeTokens(@NotNull HttpServletResponse response,
      @NotNull OAuth2AccessToken accessToken, @Nullable OAuth2RefreshToken refreshToken) {
    Instant expiresAt = accessToken.getExpiresAt();
    LOGGER.debug("storeTokens expAt='{}'", expiresAt);
    storeAccessJwtCookie(response, accessToken.getTokenValue(), expiresAt);
    if (refreshToken != null) {
      Instant issuedAt = refreshToken.getIssuedAt();
      String value = (issuedAt != null)
          ? refreshToken.getTokenValue() + ":" + issuedAt.toEpochMilli()
          : refreshToken.getTokenValue();
      setTokenCookie(response, COOKIE_REFRESH_TOKEN, value, refreshToken.getExpiresAt());
    }
  }

  @NotNull
  public Optional<RefreshedTokens> refreshTokens(@NotNull HttpServletRequest req) {
    if (WebUtils.getCookie(req, COOKIE_REFRESH_TOKEN) == null) {
      return Optional.empty();
    }
    Optional<OAuth2AccessToken> accessToken = getAccessTokenFromCookie(req);
    if (accessToken.filter(this::canSkipAccessTokenRefresh).isPresent()) {
      return Optional.empty();
    }
    OAuth2RefreshToken refreshToken = getRefreshToken(req).orElseThrow(() ->
        new OAuth2AuthorizationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
            "Malformed refresh cookie", null)));
    // Spring 5.7 requires access-token metadata, but never sends this placeholder.
    OAuth2AccessToken grantAccessToken = accessToken.orElseGet(() -> new OAuth2AccessToken(
        OAuth2AccessToken.TokenType.BEARER, "refresh-grant-metadata", null, null, Set.of()));
    var registration = registrationRepo.findByRegistrationId(identityService.getRegistrationId());
    // Concurrent refreshes rely on Keycloak reuse settings:
    // docs/adr/0002-token-refresh-concurrency.md.
    var result = refreshClient.getTokenResponse(new OAuth2RefreshTokenGrantRequest(
        registration, grantAccessToken, refreshToken));
    OAuth2RefreshToken renewedRefreshToken = result.getRefreshToken();
    if (shouldRetainOriginalRefreshToken(refreshToken, renewedRefreshToken)) {
      renewedRefreshToken = refreshToken;
    }
    return Optional.of(new RefreshedTokens(result.getAccessToken(), renewedRefreshToken));
  }

  private boolean canSkipAccessTokenRefresh(OAuth2AccessToken accessToken) {
    return (accessToken.getExpiresAt() == null)
        || !Instant.now().isAfter(accessToken.getExpiresAt().minus(REFRESH_SKEW));
  }

  private boolean shouldRetainOriginalRefreshToken(OAuth2RefreshToken originalToken,
      @Nullable OAuth2RefreshToken returnedToken) {
    return (returnedToken == null)
        || originalToken.getTokenValue().equals(returnedToken.getTokenValue());
  }

  public record RefreshedTokens(OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) {}

  /**
   * @param request
   *          the request
   * @return the Refresh Token or optional.empty if none found or invalid
   */
  @NotNull
  public Optional<OAuth2RefreshToken> getRefreshToken(@NotNull HttpServletRequest req) {
    return getTokenValue(req, CookieTokenService.COOKIE_REFRESH_TOKEN)
        .map(val -> val.split(":", 2))
        .filter(parts -> StringUtils.hasText(parts[0]))
        .map(parts -> {
          String tokenValue = parts[0];
          final Instant issuedAt = convertIssuedAt(parts);
          LOGGER.info("getRefreshToken issuedAt='{}'",
              defer(() -> (issuedAt == null) ? "n/a" : PATTERN_FMT.format(issuedAt)));
          return new OAuth2RefreshToken(tokenValue, issuedAt);
        });
  }

  private Instant convertIssuedAt(String[] parts) {
    Instant issuedAt = null;
    if (parts.length == 2) {
      try {
        issuedAt = Instant.ofEpochMilli(Long.parseLong(parts[1]));
      } catch (NumberFormatException e) {
        issuedAt = null;
      }
    }
    return issuedAt;
  }

  @NotNull
  public Optional<String> getAccessToken(@NotNull HttpServletRequest req) {
    return Optional.ofNullable((String) req.getAttribute(REFRESHED_ACCESS_TOKEN_ATTRIBUTE))
        .or(() -> getAccessTokenFromCookie(req).map(OAuth2AccessToken::getTokenValue));
  }

  /**
   * Resolve any
   * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
   * Token</a> value from the access_token cookie in the request.
   *
   * @param request
   *          the request
   * @return the Bearer Access Token or optional.empty if none found or invalid
   */
  @NotNull
  public Optional<OAuth2AccessToken> getAccessTokenFromCookie(@NotNull HttpServletRequest req) {
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

  private void setTokenCookie(@NotNull HttpServletResponse response, @NotEmpty String cookieName,
      @Nullable String value, @Nullable Instant expiry) {
    Assert.notNull(response, "Response must not be null");
    Assert.hasText(cookieName, "cookieName must not be null nor empty");
    LOGGER.trace("setTokenCookie '{}'", cookieName);
    Cookie cookie = new Cookie(cookieName, value);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath("/");
    if (expiry != null) {
      long maxAge = (expiry.getEpochSecond() - Instant.now().getEpochSecond());
      cookie.setMaxAge((int) maxAge);
    }
    response.addCookie(cookie);
  }

  @NotNull
  private Optional<Jwt> getJwtFromCookie(@NotNull HttpServletRequest req,
      @NotEmpty String cookieName) {
    Assert.notNull(req, "Request must not be null");
    Assert.hasText(cookieName, "cookieName must not be null nor empty");
    try {
      return getTokenValue(req, cookieName)
          .map(val -> identityService.getJwtDecoder().decode(val));
    } catch (JwtException exp) {
      if (LOGGER.isTraceEnabled()) {
        LOGGER.trace("decoding the jwt cookie '{}' value failed.", cookieName, exp);
      } else {
        LOGGER.info("decoding the jwt cookie '{}' value failed.", cookieName);
      }
    }
    return Optional.empty();
  }

  private Set<String> getScopesFromJwt(Jwt jwt) {
    // sometimes Keycloak uses "scp" instead
    List<String> scopes = Stream.of("scope", "scp")
        .map(jwt::getClaimAsStringList)
        .filter(Objects::nonNull)
        .findFirst().orElse(List.of());
    return new HashSet<>(scopes);
  }

}
