package com.celements.spring.security.web;

import static com.celements.execution.XWikiExecutionProp.*;
import static com.celements.logging.LogUtils.*;

import java.util.Optional;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.xwiki.context.Execution;
import org.xwiki.model.reference.WikiReference;

import com.celements.spring.security.api.IdentityService;
import com.celements.wiki.service.WikiManagerService;

@Component
public class OAuth2TenantRequestMatcher implements RequestMatcher {

  private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2TenantRequestMatcher.class);

  private final IdentityService identityService;
  private final WikiManagerService wikiManager;
  private final Execution execution;

  @Inject
  public OAuth2TenantRequestMatcher(
      IdentityService identityService,
      WikiManagerService wikiManager,
      Execution execution) {
    this.identityService = identityService;
    this.wikiManager = wikiManager;
    this.execution = execution;
  }

  /**
   * evaluates if the current request-tenant has an enabled oicd configuration and thus should be
   * handled by the security chain.
   */
  @Override
  public boolean matches(HttpServletRequest request) {
    boolean oicdEnabled = getWikiRef().map(wikiManager::isOicdEnabled).orElse(false);
    boolean configValid = identityService.isConfigValid();
    LOGGER.debug("check oicd config for '{}', oicdEnabled '{}', configValid '{}'",
        defer(() -> getWikiRef().orElse(null)), oicdEnabled, configValid);
    return oicdEnabled && configValid;
  }

  private Optional<WikiReference> getWikiRef() {
    return Optional.ofNullable(execution.getContext())
        .flatMap(eContext -> eContext.get(WIKI));
  }

}
