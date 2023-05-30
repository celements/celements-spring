package com.celements.spring.mvc;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;

import com.celements.init.XWikiRequestInitializer;

@Component
public class XWikiSpringInterceptor implements CelMvcInterceptor {

  private final XWikiRequestInitializer xwikiRequestInitializer;

  @Inject
  public XWikiSpringInterceptor(XWikiRequestInitializer initializer) {
    this.xwikiRequestInitializer = initializer;
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {
    xwikiRequestInitializer.init("spring", request, response);
    return true;
  }

  @Override
  public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
      Object handler, Exception ex) throws Exception {
    xwikiRequestInitializer.cleanup();
  }

}
