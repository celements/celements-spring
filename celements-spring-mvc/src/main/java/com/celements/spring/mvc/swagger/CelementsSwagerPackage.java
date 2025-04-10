package com.celements.spring.mvc.swagger;

public class CelementsSwagerPackage implements RequestHandlerPackage {

  @Override
  public String basePackage() {
    return "com.celements";
  }

}
