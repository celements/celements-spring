package com.celements.spring.security.oauth2.cookietoken;

import java.time.Instant;
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
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
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

  private final WikiClientRegistrationRepository registrationRepo;
  private final IdentityService identityService;
  private final OAuth2AuthorizedClientManager authorizedClientManager;

  @Inject
  public CookieTokenService(
      WikiClientRegistrationRepository registrationRepo,
      IdentityService identityService,
      OAuth2AuthorizedClientManager authorizedClientManager) {
    this.registrationRepo = registrationRepo;
    this.identityService = identityService;
    this.authorizedClientManager = authorizedClientManager;
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
    // Set as HttpOnly cookies
    setTokenCookie(response, COOKIE_ACCESS_TOKEN, accessToken.getTokenValue(),
        accessToken.getExpiresAt());
    if (refreshToken != null) {
      setTokenCookie(response, COOKIE_REFRESH_TOKEN, refreshToken.getTokenValue(),
          refreshToken.getExpiresAt());
    }
  }

  @NotNull
  public Optional<OAuth2AuthorizedClient> refreshTokens(@NotNull HttpServletRequest req) {
    Optional<OAuth2AuthorizedClient> oldClientOpt = reconstructAuthClientFromCookie(req);
    return oldClientOpt
        .map(existingClient -> OAuth2AuthorizeRequest
            .withClientRegistrationId(identityService.getRegistrationId())
            .principal(existingClient.getPrincipalName())
            // here's where you hand Spring your pre‐built client:
            .attribute(OAuth2AuthorizedClient.class.getName(), existingClient)
            .build())
        .map(authorizedClientManager::authorize)
        .filter(client -> hasAccessTokenChanged(oldClientOpt, client)
            || hasRefreshTokenChanged(oldClientOpt, client));
  }

  boolean hasRefreshTokenChanged(Optional<OAuth2AuthorizedClient> oldClientOpt,
      OAuth2AuthorizedClient client) {
    return equalsTokenValues(oldClientOpt, client, OAuth2AuthorizedClient::getRefreshToken);
  }

  boolean hasAccessTokenChanged(Optional<OAuth2AuthorizedClient> oldClientOpt,
      OAuth2AuthorizedClient client) {
    return equalsTokenValues(oldClientOpt, client, OAuth2AuthorizedClient::getAccessToken);
  }

  @NotNull
  private Optional<OAuth2AuthorizedClient> reconstructAuthClientFromCookie(
      @NotNull HttpServletRequest req) {
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
    return Optional.empty();
  }

  /**
   * @param request
   *          the request
   * @return the Refresh Token or optional.empty if none found or invalid
   */
  @NotNull
  private Optional<OAuth2RefreshToken> getRefreshTokenFromCookie(@NotNull HttpServletRequest req) {
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
      LOGGER.debug("decoding the jwt cookie '{}' value failed.", cookieName, exp);
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
