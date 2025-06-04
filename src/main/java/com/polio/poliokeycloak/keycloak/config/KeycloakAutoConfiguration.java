package com.polio.poliokeycloak.keycloak.config;

import com.polio.poliokeycloak.keycloak.client.prop.KeycloakSecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(KeycloakSecurityProperties.class)
@ComponentScan(basePackages = "com.polio.poliokeycloak.keycloak")
public class KeycloakAutoConfiguration {
    // 아무 메서드 없음, 자동 스캔과 바인딩만 처리
}
