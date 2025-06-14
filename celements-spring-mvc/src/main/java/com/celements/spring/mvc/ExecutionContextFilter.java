package com.celements.spring.mvc;

import static com.celements.logging.LogUtils.*;
import static com.celements.spring.context.SpringContextProvider.*;

import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.container.servlet.ServletContainerException;
import org.xwiki.context.ExecutionContextException;

import com.celements.init.CelementsRequestFilter;
import com.celements.wiki.WikiMissingException;

public class ExecutionContextFilter implements Filter {

  private static final Logger LOGGER = LoggerFactory.getLogger(ExecutionContextFilter.class);

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    // No initialization needed
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    CelementsRequestFilter requestFilter = getBeanFactory().getBean(CelementsRequestFilter.class);
    try {
      LOGGER.debug("setup execution context for request {}",
          defer(() -> getRequestUrl(request).orElse("'no HttpServletRequest'")));
      if ((request instanceof HttpServletRequest) && (response instanceof HttpServletResponse)) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        requestFilter.preExecute("spring", httpRequest, httpResponse);
      }
      chain.doFilter(request, response);
    } catch (ExecutionContextException | WikiMissingException | ExecutionException
        | ServletContainerException exp) {
      LOGGER.error("Failed to execute request because initialize execution context failed", exp);
    } finally {
      requestFilter.postExecute();
    }
  }

  private Optional<String> getRequestUrl(ServletRequest request) {
    if (!(request instanceof HttpServletRequest)) {
      return Optional.empty();
    }
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    StringBuilder url = new StringBuilder(httpRequest.getRequestURL());
    String query = httpRequest.getQueryString();
    if ((query != null) && !query.isEmpty()) {
      url.append('?').append(query);
    }
    return Optional.of(url.toString());
  }

  @Override
  public void destroy() {
    // No cleanup needed
  }

}
