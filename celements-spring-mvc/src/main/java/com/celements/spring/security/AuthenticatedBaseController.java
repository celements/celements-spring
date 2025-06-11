package com.celements.spring.security;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * A base controller that enforces that all extending controller methods
 * require an authenticated user by default.
 * This can be overridden on a per-method basis with annotations like @PermitAll
 * or a more specific @PreAuthorize rule.
 */
@PreAuthorize("isAuthenticated()")
public abstract class AuthenticatedBaseController {}
