package com.celements.spring.mvc;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;

import com.celements.init.XWikiSessionInitialiser;

@Component
public class XWikiSpringInterceptor implements CelMvcInterceptor {

  private final XWikiSessionInitialiser xwikiSessionInitializer;

  @Inject
  public XWikiSpringInterceptor(XWikiSessionInitialiser initializer) {
    this.xwikiSessionInitializer = initializer;
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {
    xwikiSessionInitializer.init("spring", request, response);
    return true;
  }

  @Override
  public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
      Object handler, Exception ex) throws Exception {
    xwikiSessionInitializer.cleanupSession();
  }

}
