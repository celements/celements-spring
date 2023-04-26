package com.celements.spring.mvc;

import javax.inject.Inject;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.xwiki.context.Execution;

import com.xpn.xwiki.XWikiContext;

@Controller
public class HelloWorldController {

  @Inject
  private BeanFactory beanFactory;

  @Inject
  public HelloWorldController(BeanFactory beanFactory) {
    this.beanFactory = beanFactory;
  }

  @GetMapping("/helloworld")
  @ResponseBody
  public String helloWorld() {
    return "Hello World!";
  }

  @GetMapping("/hellocontext")
  @ResponseBody
  public XWikiContext helloContext() {
    return (XWikiContext) beanFactory
        .getBean(Execution.class)
        .getContext()
        .getProperty(XWikiContext.EXECUTIONCONTEXT_KEY);
  }
}
