package com.celements.spring.security;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;

/**
 * A base controller that enforces that all extending controller methods
 * require an authenticated user by default.
 * This can be overridden on a per-method basis with annotations like @PermitAll
 * or a more specific @PreAuthorize rule.
 */
@RestController
@PreAuthorize("isAuthenticated()")
public abstract class AuthenticatedBaseController {}
