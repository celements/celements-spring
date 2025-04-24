package com.celements.spring.mvc;

import java.util.List;

import javax.annotation.PostConstruct;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import com.google.common.collect.ImmutableList;

@Configuration
@EnableWebMvc
public class CelMvcConfig implements WebMvcConfigurer {

  private static final Logger LOGGER = LoggerFactory.getLogger(CelMvcConfig.class);

  private final List<CelMvcInterceptor> interceptors;
  private final RequestMappingHandlerMapping requestMappingHandlerMapping;

  @Inject
  public CelMvcConfig(List<CelMvcInterceptor> interceptors,
      RequestMappingHandlerMapping requestMappingHandlerMapping) {
    this.interceptors = ImmutableList.copyOf(interceptors);
    this.requestMappingHandlerMapping = requestMappingHandlerMapping;
  }

  @PostConstruct
  public void logAllSpringMappings() {
    requestMappingHandlerMapping.getHandlerMethods()
        .forEach((key, value) -> LOGGER.warn("Mapped path: {}", key));
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    LOGGER.trace("addInterceptors: size {}", interceptors.size());
    interceptors.forEach(registry::addInterceptor);
  }

  @Bean
  public ApplicationListener<ContextRefreshedEvent> printAllMappings(
      RequestMappingHandlerMapping mapping) {
    return event -> {
      LOGGER.warn("-> Registered Spring Mappings:");
      mapping.getHandlerMethods().forEach((key, value) -> LOGGER.warn(" → {}", key));
    };
  }
}
