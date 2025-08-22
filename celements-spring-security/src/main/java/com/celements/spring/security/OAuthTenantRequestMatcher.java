package com.celements.spring.security;

import static com.celements.execution.XWikiExecutionProp.*;

import java.util.Optional;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.xwiki.context.Execution;
import org.xwiki.model.reference.WikiReference;

import com.celements.wiki.service.WikiManagerService;

@Component
public class OAuthTenantRequestMatcher implements RequestMatcher {

  private static final Logger LOGGER = LoggerFactory.getLogger(OAuthTenantRequestMatcher.class);

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
    boolean oicdEnabled = getWikiRef().map(wikiManager::isOicdEnabled).orElse(false);
    boolean configValid = identityService.isConfigValid();
    LOGGER.debug("check oicd config for [{}], oicdEnabled={}, configValid={}", getWikiNameForLog(),
        oicdEnabled, configValid);
    return oicdEnabled && configValid;
  }

  private String getWikiNameForLog() {
    return getWikiRef().map(WikiReference::getName).orElse("no wiki found");
  }

  private Optional<WikiReference> getWikiRef() {
    return Optional.ofNullable(execution.getContext())
        .flatMap(eContext -> eContext.get(WIKI));
  }

}
