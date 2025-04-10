package com.celements.spring.mvc;

import java.util.List;

import javax.inject.Inject;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
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

  @Override
  public void addResourceHandlers(ResourceHandlerRegistry registry) {
    // Required for serving the main UI HTML page
    registry.addResourceHandler("/swagger-ui.html")
        .addResourceLocations("classpath:/META-INF/resources/");

    // Required for serving CSS/JS/fonts/images used by the UI
    registry.addResourceHandler("/webjars/**")
        .addResourceLocations("classpath:/META-INF/resources/webjars/");
  }
}
