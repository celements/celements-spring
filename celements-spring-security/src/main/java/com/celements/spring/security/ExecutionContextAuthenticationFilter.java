package com.celements.spring.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;
import org.xwiki.context.Execution;

import com.celements.execution.XWikiExecutionProp;
import com.xpn.xwiki.user.api.XWikiUser;

public class ExecutionContextAuthenticationFilter extends OncePerRequestFilter {

  private static final Logger LOGGER = LoggerFactory
      .getLogger(ExecutionContextAuthenticationFilter.class);

  private final Execution execution;

  public ExecutionContextAuthenticationFilter(Execution execution) {
    this.execution = execution;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if ((auth != null) && auth.isAuthenticated()
        && (auth instanceof OAuth2AuthenticationToken)) {
      LOGGER.info("is authenticated with user '{}'", auth.getName());
      execution.getContext().set(XWikiExecutionProp.XWIKI_USER, new XWikiUser(auth.getName()));
    } else if (auth != null) {
      LOGGER.info("is '{}' authenticated with user '{}', auth-class '{}'", auth.isAuthenticated(),
          auth.getName(), auth.getClass());
    } else {
      LOGGER.info("is NOT authenticated with user '{}'", "null");
    }
    filterChain.doFilter(request, response);
  }

}
