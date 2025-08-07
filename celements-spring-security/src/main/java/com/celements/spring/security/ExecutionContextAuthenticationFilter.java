package com.celements.spring.security;

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
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;
import org.xwiki.context.Execution;

import com.celements.auth.user.User;
import com.celements.auth.user.UserService;
import com.celements.execution.XWikiExecutionProp;

public class ExecutionContextAuthenticationFilter extends OncePerRequestFilter {

  private static final Logger LOGGER = LoggerFactory
      .getLogger(ExecutionContextAuthenticationFilter.class);

  private final Execution execution;
  private final UserService userService;

  public ExecutionContextAuthenticationFilter(UserService userService, Execution execution) {
    this.userService = userService;
    this.execution = execution;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if ((auth != null) && auth.isAuthenticated()) {
      String userId = auth.getName(); // the GUID (sub)
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
            userService.getPossibleLoginFields());
        if (userOpt.isPresent()) {
          User user = userOpt.get();
          LOGGER.debug("setting xwiki username='{}', email='{}'", user.asXWikiUser().getUser(),
              user.email());
          execution.getContext().set(XWikiExecutionProp.XWIKI_USER, user.asXWikiUser());
        }
      }
    } else if (auth != null) {
      LOGGER.info("is '{}' authenticated with user '{}', principal='{}', auth-class '{}'",
          auth.isAuthenticated(), auth.getName(), auth.getPrincipal(), auth.getClass());
    } else {
      LOGGER.info("is NOT authenticated with user '{}'", "null");
    }
    filterChain.doFilter(request, response);
  }

}
