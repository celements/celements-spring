package com.celements.spring.mvc;

import java.util.List;

import javax.inject.Inject;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.google.common.collect.ImmutableList;

@Configuration
@EnableWebMvc
public class CelMvcConfig implements WebMvcConfigurer {

  private final List<CelMvcInterceptor> interceptors;

  @Inject
  public CelMvcConfig(List<CelMvcInterceptor> interceptors) {
    this.interceptors = ImmutableList.copyOf(interceptors);
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    interceptors.forEach(registry::addInterceptor);
  }
}
