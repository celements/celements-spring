package com.celements.spring.security;

import static com.celements.logging.LogUtils.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.model.reference.ClassReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.observation.event.Event;

import com.celements.common.observation.listener.AbstractLocalEventListener;
import com.celements.configuration.CelementsFromWikiConfigurationSource;
import com.celements.model.reference.RefBuilder;
import com.celements.observation.save.SaveEventOperation;
import com.celements.observation.save.object.ObjectEvent;
import com.google.common.base.Objects;
import com.xpn.xwiki.XWikiConstant;
import com.xpn.xwiki.doc.XWikiDocument;

@Component
public class KeycloakService implements IdentityService {

  private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakService.class);

  private final Map<String, AuthenticationManager> authManagerCache = new ConcurrentHashMap<>();

  private final ConfigurationSource configSource;

  @Inject
  public KeycloakService(
      @Named(CelementsFromWikiConfigurationSource.NAME) ConfigurationSource configSource) {
    this.configSource = configSource;
    LOGGER.info("KeycloakService constructor: {} host={}, realm={}", configSource.getClass(),
        getHost(), getRealm());
  }

  @Override
  @NotEmpty
  public String getHost() {
    return configSource.getProperty("celements.keycloak.host", "localhost");
  }

  @Override
  @NotEmpty
  public String getRealm() {
    return configSource.getProperty("celements.keycloak.realm", XWikiConstant.MAIN_WIKI.getName());
  }

  @Override
  @NotEmpty
  public String getJwkSetUri() {
    return "https://" + getHost() + "/realms/" + getRealm()
        + "/protocol/openid-connect/certs";
  }

  @Override
  @NotNull
  public AuthenticationManager getAuthenticationManagerForWiki(WikiReference wikiRef) {
    return authManagerCache.computeIfAbsent(wikiRef.getName(),
        this::buildAuthenticationManagerForWiki);
  }

  private AuthenticationManager buildAuthenticationManagerForWiki(String wikiName) {
    LOGGER.info("Building JwtDecoder for wikiName={}, jwkSetUri={}", wikiName,
        defer(this::getJwkSetUri));
    JwtAuthenticationProvider provider = new JwtAuthenticationProvider(
        NimbusJwtDecoder.withJwkSetUri(getJwkSetUri()).build());
    provider.setJwtAuthenticationConverter(jwtAuthConverter());
    return new ProviderManager(provider);
  }

  private JwtAuthenticationConverter jwtAuthConverter() {
    JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
    authoritiesConverter.setAuthoritiesClaimName("realm_access.roles");
    authoritiesConverter.setAuthorityPrefix("ROLE_");

    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
    return converter;
  }

  @Component(AuthCacheInvalidationListener.NAME)
  public class AuthCacheInvalidationListener
      extends AbstractLocalEventListener<XWikiDocument, Object> {

    public static final String NAME = "keycloakServiceAuthCacheInvalidationListener";

    private final Logger logger = LoggerFactory.getLogger(AuthCacheInvalidationListener.class);

    @Override
    public List<Event> getEvents() {
      logger.info("getEvents: registering for document update events.");
      return List.of(
          new ObjectEvent(SaveEventOperation.CREATED, getXWikiPreferencesClassRef()),
          new ObjectEvent(SaveEventOperation.UPDATED, getXWikiPreferencesClassRef()));
    }

    @Override
    public String getName() {
      return NAME;
    }

    private ClassReference getXWikiPreferencesClassRef() {
      return RefBuilder.create().space(XWikiConstant.XWIKI_SPACE)
          .doc(XWikiConstant.XWIKI_PREF_DOC_NAME).build(ClassReference.class);
    }

    @Override
    protected void onEventInternal(@NotNull Event event, @NotNull XWikiDocument changedDoc,
        @Nullable Object data) {
      if (Objects.equal(changedDoc.getDocumentReference(),
          context.getXWikiPreferencesDocRef())) {
        logger.trace("changes on {} saved. Invalidating authentication manager cache",
            changedDoc.getDocumentReference());
        authManagerCache.remove(changedDoc.getWikiRef().getName());
      } else {
        logger.trace("changes on {} saved. NOT invalidating authentication manager cache",
            changedDoc.getDocumentReference());
      }
    }

  }
}
