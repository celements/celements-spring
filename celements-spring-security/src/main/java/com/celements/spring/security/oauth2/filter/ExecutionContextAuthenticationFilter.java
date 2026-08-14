package com.celements.spring.security.oauth2.filter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;
import org.xwiki.context.Execution;

import com.celements.auth.MainAdminConfig;
import com.celements.auth.user.User;
import com.celements.auth.user.UserInstantiationException;
import com.celements.auth.user.UserService;
import com.celements.execution.XWikiExecutionProp;
import com.xpn.xwiki.user.api.XWikiUser;

public class ExecutionContextAuthenticationFilter extends OncePerRequestFilter {

  private static final Logger LOGGER = LoggerFactory
      .getLogger(ExecutionContextAuthenticationFilter.class);

  private final UserService userService;
  private final MainAdminConfig mainAdminConfig;
  private final Execution execution;

  public ExecutionContextAuthenticationFilter(
      UserService userService,
      MainAdminConfig mainAdminConfig,
      Execution execution) {
    this.userService = userService;
    this.mainAdminConfig = mainAdminConfig;
    this.execution = execution;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    var securityContext = SecurityContextHolder.getContext();
    autoLogin(securityContext)
        .or(() -> processAuthentication(securityContext))
        .ifPresent(user -> execution.getContext().set(XWikiExecutionProp.XWIKI_USER, user));
    filterChain.doFilter(request, response);
  }

  private Optional<XWikiUser> processAuthentication(SecurityContext securityContext) {
    Authentication auth = securityContext.getAuthentication();
    if ((auth != null) && auth.isAuthenticated()) {
      String userId = auth.getName(); // the Keycloak GUID (sub)
      String username;
      String email;
      if (auth instanceof JwtAuthenticationToken) {
        JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) auth;
        Jwt jwt = jwtAuth.getToken();
        username = jwt.getClaimAsString("preferred_username");
        email = jwt.getClaimAsString("email");
      } else if (auth instanceof OAuth2AuthenticationToken) {
        OAuth2AuthenticationToken oauth2 = (OAuth2AuthenticationToken) auth;
        OAuth2User principal = oauth2.getPrincipal();
        username = principal.getAttribute("preferred_username");
        email = principal.getAttribute("email");
      } else {
        // fallback e.g. for other auth types
        username = userId;
        email = null;
      }
      LOGGER.info("is authenticated with user '{}', username='{}', email='{}'", auth.getName(),
          username, email);
      if (username != null) {
        Optional<User> userOpt = userService.getPossibleUserForLoginField(username,
            Set.of("email"));
        if (userOpt.isPresent()) {
          User user = userOpt.get();
          LOGGER.debug("setting xwiki isGlobal='{}', username='{}', email='{}'", user.isGlobal(),
              user.asXWikiUser().getUser(), user.email());
          return Optional.of(user.asXWikiUser());
        } else {
          LOGGER.info("no celements user found for email='{}'", email);
        }
      }
    } else if (auth != null) {
      LOGGER.info("is '{}' authenticated with user '{}', principal='{}', auth-class '{}'",
          auth.isAuthenticated(), auth.getName(), auth.getPrincipal(), auth.getClass());
    } else {
      LOGGER.info("is NOT authenticated with user '{}'", "null");
    }
    return Optional.empty();
  }

  private Optional<XWikiUser> autoLogin(SecurityContext securityContext) {
    if (!mainAdminConfig.isAutoLoginEnabled()) {
      return Optional.empty();
    }
    var xwikiUser = mainAdminConfig.getXWikiUser();
    var auth = new UsernamePasswordAuthenticationToken(xwikiUser.getUser(), null, List.of());
    securityContext.setAuthentication(auth);
    return Optional.of(xwikiUser);
  }

}
