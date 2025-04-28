package com.celements.spring.mvc;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springdoc.core.SpringDocConfigProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.google.common.collect.ImmutableList;

@Configuration
@EnableWebMvc
@EnableConfigurationProperties(SpringDocConfigProperties.class)
@Import({
    org.springdoc.core.SpringDocConfiguration.class,
    org.springdoc.webmvc.core.SpringDocWebMvcConfiguration.class
})
public class CelMvcConfig implements WebMvcConfigurer {

  private static final Logger LOGGER = LoggerFactory.getLogger(CelMvcConfig.class);

  private final List<CelMvcInterceptor> interceptors;

  @Inject
  public CelMvcConfig(List<CelMvcInterceptor> interceptors) {
    this.interceptors = ImmutableList.copyOf(interceptors);
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    LOGGER.trace("addInterceptors: size {}", interceptors.size());
    interceptors.forEach(registry::addInterceptor);
  }
}
