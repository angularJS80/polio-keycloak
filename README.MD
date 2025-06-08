# 🔐 polio-keycloak

Spring Cloud Gateway에서 [Keycloak](https://www.keycloak.org/)과 연동하여 URI별 인가 정책을 자동 구성하는 SDK입니다.

> 인가 로직을 코드에서 분리하고, Keycloak 정책에 따라 동적으로 적용할 수 있도록 설계되었습니다.

## 🏗️ polio 인가 아키텍처

Keycloak 기반의 동적 인가 구조를 Spring Cloud Gateway에 연동하여, 실시간 권한 반영과 API 보호를 실현합니다.

---

### 📌 구성요소 역할 분리

#### 🧩 `polio-gateway`
> **인가 문지기 + API 전달자**

- 클라이언트 요청 수신
- HTTP Method / URL 기반 Scope 추론
- `polio-keycloak` SDK 호출 → Keycloak UMA Ticket 인가 위임
- 인가 성공 시 API 전달, 실패 시 403 반환

#### 🧩 `polio-keycloak`
> **Keycloak 연동 SDK (Gateway 내부 포함)**

- Keycloak Resource, Scope, Permission 자동 조회 및 매핑
- Protection API 기반 인가 요청 생성
- `grant_type=uma-ticket` 기반 인가 요청 수행
- Gateway의 인가 처리 핵심

#### 🧩 `polio-api`
> **비즈니스 로직 담당 API**

- 인가 로직은 없음
- Gateway를 통해 보호되며, 인가된 요청만 수신
- 정책 변경 시 재배포 불필요

---

### 🔄 요청 흐름

```plaintext
[Client]
   |
   | HTTP 요청
   v
[polio-gateway]
   |
   | → URI 및 Method 기반 Scope 추론
   | → polio-keycloak SDK 호출
   | → Keycloak에 인가 요청 (UMA Ticket)
   |
   | (인가 통과 시)
   v
[polio-api] ← 실제 요청 처리


---

## 📦 설치 (Gradle)

```groovy
implementation 'com.github.angularJS80:polio-keycloak:f26432e4'

## 💡 적용 예시 (`polio-gateway`)

Spring Cloud Gateway에서 `polio-keycloak`을 활용해 URI 기반 인가 처리를 구성한 예시입니다.

---

### 🔧 1. Security Config 설정

```java
http
  .authorizeExchange(authz -> {
      permissionRuleUriMapper.configureAuthorization(authz); // URI별 인가 설정
      authz.anyExchange().authenticated(); // 기본적으로 인증 필요
  })
  .oauth2ResourceServer(oauth2 -> 
      oauth2.jwt(jwt -> 
          jwt.jwtAuthenticationConverter(converter.buildConverter())
      )
  );

---

## 🛠️ 2. PermissionRuleUriMapper 구현

Keycloak에서 가져온 URI 및 Permission 정보를 기반으로 인가 처리를 설정합니다.

```java
@Component
@RequiredArgsConstructor
public class PermissionRuleUriMapper {

    private final KeycloakPermissionService keycloakPermissionService;

    public void configureAuthorization(ServerHttpSecurity.AuthorizeExchangeSpec authz) {
        keycloakPermissionService.getUris().forEach(uri -> {
            if (keycloakPermissionService.isNoPermission(uri)) {
                authz.pathMatchers(uri).permitAll(); // 인증 없이 접근 허용
            } else {
                authz.pathMatchers(uri)
                     .access((authentication, context) -> check(authentication, context, uri));
            }
        });
    }

    private Mono<AuthorizationDecision> check(Mono<Authentication> authentication, AuthorizationContext context, String uri) {
        return authentication.map(auth -> 
            new AuthorizationDecision(keycloakPermissionService.umaCheck(context, auth, uri))
        );
    }
}

## 🔐 3. Keycloak 전용 JWT 권한 변환기

Keycloak에서 발급한 JWT의 클레임(`realm_access`, `resource_access` 등)에서 권한 정보를 추출하여 `GrantedAuthority`로 변환합니다. 이 변환기는 Spring Security의 `ReactiveJwtAuthenticationConverter`에 연결되어 사용됩니다.

### 📦 클래스: `KeycloakReactiveJwtAuthenticationConverter`

```java
package com.polio.gateway.security.converter;

import com.polio.gateway.security.util.JwtUtil;
import com.polio.poliokeycloak.keycloak.client.prop.KeycloakSecurityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.*;

@Component
@RequiredArgsConstructor
public class KeycloakReactiveJwtAuthenticationConverter implements Converter<Jwt, Flux<GrantedAuthority>> {

    private final KeycloakSecurityProperties keycloakSecurityProperties;

    @Override
    public Flux<GrantedAuthority> convert(Jwt jwt) {
        return Flux.fromIterable(JwtUtil.convertAuthorities(jwt, keycloakSecurityProperties.getClientId()));
    }

    public ReactiveJwtAuthenticationConverter buildConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(this); // 현재 클래스가 converter 역할을 수행
        return converter;
    }
}

