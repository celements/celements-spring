package com.celements.spring.mvc;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import com.google.common.collect.ImmutableList;

@Configuration
@EnableWebMvc
public class CelMvcConfig implements WebMvcConfigurer {

  private static final Logger LOGGER = LoggerFactory.getLogger(CelMvcConfig.class);

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
    LOGGER.warn("addResourceHandlers in CelMvcConfig start");
    // Required for serving the main UI HTML page
    registry.addResourceHandler("/swagger-ui.html")
        .addResourceLocations("classpath:/META-INF/resources/");

    // Required for serving CSS/JS/fonts/images used by the UI
    registry.addResourceHandler("/webjars/**")
        .addResourceLocations("classpath:/META-INF/resources/webjars/");

    LOGGER.warn("addResourceHandlers in CelMvcConfig end");
  }

  @Bean
  public ApplicationListener<ContextRefreshedEvent> mappingPrinter(
      List<RequestMappingHandlerMapping> mappingList) {
    return event -> {
      LOGGER.warn("Registered Mappings:");
      mappingList.stream().forEach(mapping -> mapping.getHandlerMethods()
          .forEach((key, value) -> LOGGER.warn(" → {}", key)));
    };
  }
}
