package com.celements.store.api;

import javax.inject.Inject;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.celements.auth.user.User;
import com.celements.rights.access.IRightsAccessFacadeRole;
import com.celements.spring.security.AuthenticatedBaseController;
import com.celements.store.DocumentCacheStore;
import com.celements.store.DocumentCacheStore.Metrics;

// TODO extract generic administrative controllers into a celements-admin-api module
@RestController
@RequestMapping("/v1/doc-cache")
@PreAuthorize("permitAll()") // endpoints are protected by requireSuperAdmin
public class DocumentCacheController extends AuthenticatedBaseController {

  private final DocumentCacheStore store;
  private final IRightsAccessFacadeRole rightsAccess;

  @Inject
  public DocumentCacheController(
      DocumentCacheStore store,
      IRightsAccessFacadeRole rightsAccess) {
    this.store = store;
    this.rightsAccess = rightsAccess;
  }

  @GetMapping
  public Metrics getMetrics() {
    requireSuperAdmin();
    return store.getMetrics();
  }

  @DeleteMapping
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void clear() {
    requireSuperAdmin();
    store.clearCache();
  }

  private void requireSuperAdmin() {
    User user = checkAuth().orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    if (!rightsAccess.isSuperAdmin(user)) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN);
    }
  }

}
