package com.celements.spring.security.oauth2.wiki;

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

import com.celements.spring.security.oauth2.IdentityService;
import com.celements.wiki.WikiDescriptorService;

/**
 * evaluates if the current request-tenant has an enabled oicd configuration
 * and thus should be handled by the security chain.
 */
@Component
public class TenantOicdActiveRequestMatcher implements RequestMatcher {

  private static final Logger LOGGER = LoggerFactory
      .getLogger(TenantOicdActiveRequestMatcher.class);

  private final IdentityService identityService;
  private final WikiDescriptorService wikiManager;
  private final Execution execution;

  @Inject
  public TenantOicdActiveRequestMatcher(
      IdentityService identityService,
      WikiDescriptorService wikiManager,
      Execution execution) {
    this.identityService = identityService;
    this.wikiManager = wikiManager;
    this.execution = execution;
  }

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
