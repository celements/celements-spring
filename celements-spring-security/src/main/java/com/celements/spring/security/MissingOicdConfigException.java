package com.celements.spring.security;

public class MissingOicdConfigException extends Exception {

  private static final long serialVersionUID = 1L;

  public MissingOicdConfigException(String message) {
    super(message);
  }

}
