package com.celements.spring.security.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.celements.spring.security.api.IdentityService;

public class WikiAuthenticationEntryPoint implements AuthenticationEntryPoint {

  private static final Logger LOGGER = LoggerFactory.getLogger(WikiAuthenticationEntryPoint.class);

  private final IdentityService identityService;

  public WikiAuthenticationEntryPoint(IdentityService identityService) {
    this.identityService = identityService;
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {
    String loginUrl = identityService.getLoginUrl();
    LOGGER.debug("send login page redirect {}", loginUrl);
    response.sendRedirect(request.getContextPath() + loginUrl);
  }

}
