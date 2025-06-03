package com.celements.spring.security;

import javax.validation.constraints.NotEmpty;

public interface IdentityServer {

  @NotEmpty
  String getHost();

  @NotEmpty
  String getRealm();

}
