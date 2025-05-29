package com.celements.spring.security;

import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

public class SecurityWebApplicationInitializer
    extends AbstractSecurityWebApplicationInitializer {

  public SecurityWebApplicationInitializer() {
    super(WebSecurityConfig.class);
  }
}
