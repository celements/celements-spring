package com.celements.spring.mvc.swagger;

import static com.google.common.base.Predicates.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.inject.Inject;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.xwiki.configuration.ConfigurationSource;

import com.google.common.base.Predicate;

import springfox.documentation.RequestHandler;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig {

  private List<RequestHandlerPackage> reqHandlerPackageList;

  @Inject
  public SwaggerConfig(ConfigurationSource configSource,
      List<RequestHandlerPackage> reqHandlerPackageList) {
    this.reqHandlerPackageList = reqHandlerPackageList;
  }

  @Bean
  public Docket api() {

    return new Docket(DocumentationType.SWAGGER_2)
        .select()
        .apis(getBasePackages())
        .paths(PathSelectors.any())
        .build();
  }

  private Predicate<RequestHandler> getBasePackages() {
    Stream<RequestHandlerPackage> theStream = reqHandlerPackageList.stream();
    Stream<Predicate<RequestHandler>> basePkgStream = theStream
        .map(basePkg -> RequestHandlerSelectors.basePackage(basePkg.basePackage()));
    List<Predicate<RequestHandler>> basePkgList = basePkgStream
        .collect(Collectors.toList());
    return or(basePkgList);
  }
}
