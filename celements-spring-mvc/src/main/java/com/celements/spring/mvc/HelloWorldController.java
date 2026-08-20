package com.celements.spring.mvc;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.celements.spring.security.AuthenticatedBaseController;

@RestController
public class HelloWorldController extends AuthenticatedBaseController {

  @GetMapping
  @PreAuthorize("permitAll()")
  public String helloWorld() {
    return "Hello World!";
  }

}
