package com.celements.spring.security;

import static com.celements.execution.XWikiExecutionProp.*;

import java.util.Optional;
import java.util.function.Predicate;

import javax.inject.Inject;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.xwiki.context.Execution;

import com.celements.auth.user.User;
import com.celements.auth.user.UserInstantiationException;
import com.celements.auth.user.UserService;
import com.celements.rights.access.IRightsAccessFacadeRole;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiUser;

/**
 * A base controller that enforces that all extending controller methods require an authenticated
 * user by default.
 * This can be overridden on a per-method basis with annotations like @PreAuthorize("permitAll()")
 * or a more specific @PreAuthorize("hasRole('xyz')") rule.
 * WARNING: do not mix SpEL with JSR-250 annotations as it has issues
 */
@PreAuthorize("isAuthenticated()")
public abstract class AuthenticatedBaseController {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  @Inject
  private Execution execution;
  @Inject
  private UserService userService;
  @Inject
  private IRightsAccessFacadeRole rightsAccess;

  /**
   * Checks authentication via the legacy Struts auth mechanism.
   * This is necessary because the system supports Struts-only sessions that have
   * no Spring Security principal, so Spring's isAuthenticated() alone is insufficient.
   *
   * When legacy auth succeeds, the authenticated user is written back to the XWiki context so
   * downstream model services see the same current user as Struts request handling would provide.
   *
   * Long-term improvement, this bridge should move into the Spring Security filter chain so
   * legacy-authenticated users populate the SecurityContext before controller authorization runs.
   */
  protected Optional<User> checkAuth() {
    try {
      var eCtx = execution.getContext();
      XWiki xwiki = eCtx.get(XWIKI).orElseThrow();
      XWikiContext xcontext = eCtx.get(XWIKI_CONTEXT).orElseThrow();
      XWikiUser xuser = xwiki.checkAuth(xcontext);
      if (xuser != null) {
        // resolve user BEFORE setting in xcontext to avoid leaving an invalid user
        // if getUser throws (e.g. user doc/object deleted between auth and lookup)
        User user = userService.getUser(xuser.getUser());
        xcontext.setUser(xuser.getUser(), xuser.isMain());
        return Optional.of(user);
      }
    } catch (XWikiException | UserInstantiationException exc) {
      logger.warn("Failed to check auth", exc);
    }
    return Optional.empty();
  }

  protected boolean checkAuth(Predicate<User> check) {
    return check.test(checkAuth().orElse(null));
  }

  protected ResponseEntity<String> toErrorResponse(HttpStatus status, Exception e) {
    String body = rightsAccess.isSuperAdmin()
        ? ExceptionUtils.getStackTrace(e)
        : "Error: " + e.getMessage();
    return ResponseEntity.status(status).body(body);
  }

}
