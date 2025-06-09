package com.celements.spring.mvc;

import javax.annotation.security.PermitAll;
import javax.inject.Inject;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.xwiki.context.Execution;

import com.celements.execution.XWikiExecutionProp;
import com.xpn.xwiki.XWikiContext;

@RestController
public class HelloWorldController {

  private final BeanFactory beanFactory;

  @Inject
  public HelloWorldController(BeanFactory beanFactory) {
    this.beanFactory = beanFactory;
  }

  @GetMapping("/helloworld")
  @PermitAll
  public String helloWorld() {
    return "Hello World!";
  }

  @GetMapping("/hellocontext")
  public XWikiContext helloContext() {
    return beanFactory
        .getBean(Execution.class)
        .getContext()
        .get(XWikiExecutionProp.XWIKI_CONTEXT)
        .orElseThrow();
  }

}
