package com.celements.spring.mvc.swagger;

import java.util.List;

import org.springframework.stereotype.Component;

@Component
public class CelementsSwagerPackage implements RequestHandlerPackage {

  @Override
  public List<String> basePackages() {
    return List.of("com.celements");
  }

}
