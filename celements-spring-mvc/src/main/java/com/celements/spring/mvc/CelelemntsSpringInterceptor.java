package com.celements.spring.mvc;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;

import com.celements.init.CelementsRequestFilter;

@Component
public class XWikiSpringInterceptor implements CelMvcInterceptor {

  private final CelementsRequestFilter requestFilter;

  @Inject
  public XWikiSpringInterceptor(CelementsRequestFilter requestFilter) {
    this.requestFilter = requestFilter;
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {
    requestFilter.preExecute("spring", request, response);
    return true;
  }

  @Override
  public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
      Object handler, Exception ex) throws Exception {
    requestFilter.postExecute();
  }

}
