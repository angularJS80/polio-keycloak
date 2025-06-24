# 🔐 polio-keycloak

Spring Cloud Gateway에서 [Keycloak](https://www.keycloak.org/)과 연동하여 URI별 인가 정책을 자동 구성하는 SDK입니다.

> 인가 로직을 코드에서 분리하고, Keycloak 정책에 따라 동적으로 적용할 수 있도록 설계되었습니다.

---

## 🗒️ 현재 버전

- **v0.1.0**
- 커밋: `f26432e4`
- 릴리스 날짜: 2025-06-24

---

## 🏗️ polio 인가 아키텍처

Keycloak 기반의 동적 인가 구조를 Spring Cloud Gateway에 연동하여, 실시간 권한 반영과 API 보호를 실현합니다.

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

## 🔄 요청 흐름

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
