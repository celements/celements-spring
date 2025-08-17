package com.celements.spring.security;

import static com.celements.execution.XWikiExecutionProp.*;

import java.util.Optional;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.xwiki.context.Execution;
import org.xwiki.model.reference.WikiReference;

import com.celements.wiki.classes.XWikiServerClass;
import com.celements.wiki.service.WikiManagerService;

@Component
public class OAuthTenantRequestMatcher implements RequestMatcher {

  private final IdentityService identityService;
  private final WikiManagerService wikiManager;
  private final Execution execution;

  @Inject
  public OAuthTenantRequestMatcher(
      IdentityService identityService,
      WikiManagerService wikiManager,
      Execution execution) {
    this.identityService = identityService;
    this.wikiManager = wikiManager;
    this.execution = execution;
  }

  @Override
  public boolean matches(HttpServletRequest request) {
    return isOicdEnabled() && identityService.isConfigValid();
  }

  private boolean isOicdEnabled() {
    return getWikiRef()
        .flatMap(wikiManager::getWikiConfigOptional)
        .flatMap(fetcher -> fetcher.fetchField(XWikiServerClass.FIELD_OICD_ACTIVE)
            .findFirst())
        .orElse(false);
  }

  private Optional<WikiReference> getWikiRef() {
    return Optional.ofNullable(execution.getContext())
        .flatMap(eContext -> eContext.get(WIKI));
  }

}
