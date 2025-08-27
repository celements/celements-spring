package com.celements.spring.security.api;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * A base controller that enforces that all extending controller methods
 * require an authenticated user by default.
 * This can be overridden on a per-method basis with annotations like @PreAuthorize("permitAll()")
 * or a more specific @PreAuthorize("hasRole('xyz')") rule.
 * WARNING: do not mix SpEL with JSR-250 annotations as it has issues
 */
@PreAuthorize("isAuthenticated()")
public abstract class AuthenticatedBaseController {}
