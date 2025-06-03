package com.celements.spring.security;

import java.util.Optional;

public interface IdentityServer {

  Optional<String> getHost();

  String getRealm();

}
