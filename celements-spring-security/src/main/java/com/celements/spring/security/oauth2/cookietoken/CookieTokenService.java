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
import java.util.function.Function;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.web.util.WebUtils;

import com.celements.spring.security.oauth2.IdentityService;
import com.celements.spring.security.oauth2.auth.WikiClientRegistrationRepository;
import com.google.common.base.Strings;

@Service
public class CookieTokenService {

  private static final Logger LOGGER = LoggerFactory.getLogger(CookieTokenService.class);

  public static final String COOKIE_ACCESS_TOKEN = "access_token";
  public static final String COOKIE_REFRESH_TOKEN = "refresh_token";

  private static final DateTimeFormatter PATTERN_FMT = DateTimeFormatter
      .ofPattern("yyyy-MM-dd HH:mm:ss z")
      .withZone(ZoneId.systemDefault());

  private final OAuth2AuthorizedClientManager refreshOnlyAuthorizedClientManager;
  private final WikiClientRegistrationRepository registrationRepo;
  private final IdentityService identityService;

  @Inject
  public CookieTokenService(
      OAuth2AuthorizedClientRepository repo,
      WikiClientRegistrationRepository registrationRepo,
      IdentityService identityService) {
    this.registrationRepo = registrationRepo;
    this.identityService = identityService;
    this.refreshOnlyAuthorizedClientManager = refreshOnlyWebManager(repo);
  }

  @NotNull
  public Optional<String> getAccessToken(@NotNull HttpServletRequest req) {
    return getTokenValue(req, CookieTokenService.COOKIE_ACCESS_TOKEN);
  }

  @NotNull
  public Optional<String> getRefreshToken(@NotNull HttpServletRequest req) {
    return getTokenValue(req, CookieTokenService.COOKIE_REFRESH_TOKEN);
  }

  private Optional<String> getTokenValue(@NotNull HttpServletRequest req,
      @NotEmpty String cookieName) {
    return Optional.ofNullable(WebUtils.getCookie(req, cookieName))
        .map(Cookie::getValue)
        .filter(Predicate.not(Strings::isNullOrEmpty));
  }

  public void storeTokens(@NotNull HttpServletResponse response,
      @NotNull OAuth2AuthorizedClient client) {
    OAuth2AccessToken accessToken = client.getAccessToken();
    OAuth2RefreshToken refreshToken = client.getRefreshToken();
    setTokenCookie(response, COOKIE_ACCESS_TOKEN, accessToken.getTokenValue(),
        accessToken.getExpiresAt());
    if (refreshToken != null) {
      Instant issuedAt = refreshToken.getIssuedAt();
      String value = (issuedAt != null)
          ? refreshToken.getTokenValue() + ":" + issuedAt.toEpochMilli()
          : refreshToken.getTokenValue();
      setTokenCookie(response, COOKIE_REFRESH_TOKEN, value, refreshToken.getExpiresAt());
    }
  }

  private static final Duration REFRESH_SKEW = Duration.ofMinutes(2);

  private boolean shouldRefresh(@NotNull OAuth2AuthorizedClient client) {
    var access = client.getAccessToken();
    if ((access == null) || (access.getExpiresAt() == null) || (client.getRefreshToken() == null)) {
      return false;
    }
    return Instant.now().isAfter(access.getExpiresAt().minus(REFRESH_SKEW));
  }

  OAuth2AuthorizedClientManager refreshOnlyWebManager(
      OAuth2AuthorizedClientRepository repo) {
    var provider = new RefreshTokenOAuth2AuthorizedClientProvider();
    provider.setClockSkew(REFRESH_SKEW);

    var manager = new DefaultOAuth2AuthorizedClientManager(registrationRepo, repo);
    manager.setAuthorizedClientProvider(provider);
    return manager;
  }

  @NotNull
  public Optional<OAuth2AuthorizedClient> refreshTokens(@NotNull HttpServletRequest req,
      @NotNull HttpServletResponse resp) {
    var auth = SecurityContextHolder.getContext().getAuthentication();
    Optional<OAuth2AuthorizedClient> oldClientOpt = reconstructAuthClientFromCookie(req, auth);
    LOGGER.debug(
        "refresh check: authPresent='{}', accessCookie='{}', refreshCookie='{}',"
            + " existingClient='{}' expAt='{}', shouldRefresh='{}'",
        (auth != null) && auth.isAuthenticated(),
        getAccessToken(req).isPresent(),
        getRefreshToken(req).isPresent(),
        oldClientOpt.isPresent(),
        oldClientOpt.map(c -> c.getAccessToken().getExpiresAt()).orElse(null),
        oldClientOpt.map(this::shouldRefresh).orElse(false));
    LOGGER.debug("principal authName='{}' clientName='{}'",
        auth != null ? auth.getName() : null,
        defer(() -> oldClientOpt.map(OAuth2AuthorizedClient::getPrincipalName).orElse(null)));
    if ((auth != null) && auth.isAuthenticated() && oldClientOpt.isPresent()
        && shouldRefresh(oldClientOpt.get())) {
      var refreshedClientOpt = oldClientOpt
          .map(existingClient -> OAuth2AuthorizeRequest
              .withAuthorizedClient(existingClient)
              .principal(auth)
              .attribute(HttpServletRequest.class.getName(), req)
              .attribute(HttpServletResponse.class.getName(), resp)
              .build())
          .map(refreshOnlyAuthorizedClientManager::authorize)
          .map(c -> {
            LOGGER.debug("changed access='{}', changed refresh='{}'",
                hasAccessTokenChanged(oldClientOpt, c),
                hasRefreshTokenChanged(oldClientOpt, c));
            return c;
          })
          .filter(client -> hasAccessTokenChanged(oldClientOpt, client)
              || hasRefreshTokenChanged(oldClientOpt, client));
      LOGGER.debug("hasRefreshed: '{}'", refreshedClientOpt.isPresent());
      return refreshedClientOpt;
    }
    return Optional.empty();
  }

  boolean hasRefreshTokenChanged(Optional<OAuth2AuthorizedClient> oldClientOpt,
      OAuth2AuthorizedClient client) {
    var hasChanged = equalsTokenValues(oldClientOpt, client,
        OAuth2AuthorizedClient::getRefreshToken);
    LOGGER.debug("hasRefreshTokenChanged: '{}'", hasChanged);
    return hasChanged;
  }

  boolean hasAccessTokenChanged(Optional<OAuth2AuthorizedClient> oldClientOpt,
      OAuth2AuthorizedClient client) {
    var hasChanged = equalsTokenValues(oldClientOpt, client,
        OAuth2AuthorizedClient::getAccessToken);
    LOGGER.debug("hasAccessTokenChanged: '{}'", hasChanged);
    return hasChanged;
  }

  @NotNull
  private Optional<OAuth2AuthorizedClient> reconstructAuthClientFromCookie(
      @NotNull HttpServletRequest req, Authentication auth) {
    Optional<Jwt> accessJwtOpt = getJwtFromCookie(req, COOKIE_ACCESS_TOKEN);
    Optional<OAuth2RefreshToken> refreshTokenOpt = getRefreshTokenFromCookie(req);
    if (accessJwtOpt.isPresent() && refreshTokenOpt.isPresent()) {
      OAuth2AccessToken accessToken = reconstructAccessTokenFromJwt(accessJwtOpt.get());
      OAuth2RefreshToken refreshToken = refreshTokenOpt.get();
      return Optional.of(new OAuth2AuthorizedClient(
          registrationRepo.findByRegistrationId(identityService.getRegistrationId()),
          auth.getName(),
          accessToken,
          refreshToken));
    }
    return Optional.empty();
  }

  /**
   * @param request
   *          the request
   * @return the Refresh Token or optional.empty if none found or invalid
   */
  @NotNull
  private Optional<OAuth2RefreshToken> getRefreshTokenFromCookie(@NotNull HttpServletRequest req) {
    return Optional.ofNullable(WebUtils.getCookie(req, COOKIE_REFRESH_TOKEN))
        .map(Cookie::getValue)
        .filter(Predicate.not(Strings::isNullOrEmpty))
        .map(val -> {
          String[] parts = val.split(":", 2);
          String tokenValue = parts[0];
          final Instant issuedAt = convertIssuedAt(parts);
          LOGGER.info("getRefreshTokenFromCookie issuedAt='{}'",
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
    LOGGER.debug("setTokenCookie '{}'", cookieName);
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
      return Optional.ofNullable(WebUtils.getCookie(req, cookieName))
          .map(cookie -> identityService.getJwtDecoder().decode(cookie.getValue()));
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

  private boolean equalsTokenValues(Optional<OAuth2AuthorizedClient> oldClientOpt,
      OAuth2AuthorizedClient client,
      Function<? super OAuth2AuthorizedClient, ? extends AbstractOAuth2Token> getValueFunc) {
    return !Objects.equals(getOptTokenValue(oldClientOpt, getValueFunc),
        getOptTokenValue(Optional.ofNullable(client), getValueFunc));
  }

  private String getOptTokenValue(Optional<OAuth2AuthorizedClient> clientOpt,
      Function<? super OAuth2AuthorizedClient, ? extends AbstractOAuth2Token> getValueFunc) {
    return clientOpt
        .map(getValueFunc)
        .map(AbstractOAuth2Token::getTokenValue)
        .orElse(null);
  }

}
