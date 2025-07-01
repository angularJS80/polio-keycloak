package com.polio.poliokeycloak.keycloak.helper;

import com.polio.poliokeycloak.keycloak.client.prop.KeycloakSecurityProperties;
import com.polio.poliokeycloak.keycloak.helper.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
@Component
@Slf4j
public class KeycloakAuthHelper {

    private final KeycloakSecurityProperties props;
    private final RestTemplate restTemplate = new RestTemplate();

    public UserLoginResponse signIn(UserLoginRequest loginRequest) {
        String tokenUrl = props.getServerUrl() + "/realms/" + props.getRealm() + "/protocol/openid-connect/token";

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", props.getClientId());
        body.add("client_secret", props.getClientSecret());
        body.add("username", loginRequest.username());
        body.add("password", loginRequest.password());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers());

        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
        return parseTokenResponse(response);
    }


    public boolean signOut(String refreshToken) {
        String logoutUrl = props.getServerUrl() + "/realms/" + props.getRealm() + "/protocol/openid-connect/logout";

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", props.getClientId());
        body.add("client_secret", props.getClientSecret());
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers());

        try {
            ResponseEntity<Void> response = restTemplate.postForEntity(logoutUrl, request, Void.class);
            return response.getStatusCode().is2xxSuccessful();
        } catch (Exception e) {
            log.error("signOut error", e);
            return false;
        }
    }

    public UserLoginResponse refresh(String refreshToken) {
        String tokenUrl = props.getServerUrl() + "/realms/" + props.getRealm() + "/protocol/openid-connect/token";

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("client_id", props.getClientId());
        body.add("client_secret", props.getClientSecret());
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers());
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
        return parseTokenResponse(response);
    }



    public String regist(UserRegisterRequest req) {
        String url = props.getServerUrl() + "/admin/realms/" + props.getRealm() + "/users";
        String accessToken = getAdminAccessToken();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> payload = Map.of(
            "username", req.username(),
            "enabled", true,
            "email", req.email(),
            "credentials", List.of(Map.of(
                "type", "password",
                "value", req.password(),
                "temporary", false
            ))
        );

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(payload, headers);
        ResponseEntity<Void> response = restTemplate.postForEntity(url, request, Void.class);

        if (response.getStatusCode().is2xxSuccessful()) {
            URI location = response.getHeaders().getLocation();
            if (location != null) {
                return location.getPath().substring(location.getPath().lastIndexOf('/') + 1);
            }
        }
        throw new RuntimeException("사용자 등록 실패");
    }


    public UserLoginResponse tokenExchangeAsUser(ExchangeUserRequest exchangeUserRequest) {
        String tokenUrl = props.getServerUrl() + "/realms/" + props.getRealm() + "/protocol/openid-connect/token";

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        body.add("client_id", props.getClientId());
        body.add("client_secret", props.getClientSecret());
        body.add("subject_token", getAdminAccessToken());
        body.add("requested_subject", exchangeUserRequest.requestedSubject());
        body.add("audience", exchangeUserRequest.audience());
        body.add("scope", exchangeUserRequest.scope());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
        return parseTokenResponse(response);
    }


    public String findUserByEmail(String email) {
        String url = props.getServerUrl() + "/admin/realms/" + props.getRealm() + "/users?email=" + email;
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getAdminAccessToken());

        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, request, List.class);
        if (response.getBody() != null && !response.getBody().isEmpty()) {
            Map<String, Object> user = (Map<String, Object>) response.getBody().get(0);
            return (String) user.get("id");
        }
        return null;
    }

    public UserLoginResponse refreshByCode(CodeLoginRequest codeLoginRequest) {
        String tokenUrl = props.getServerUrl() + "/realms/" + props.getRealm() + "/protocol/openid-connect/token";

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", props.getClientId());
        body.add("client_secret", props.getClientSecret());
        body.add("code", codeLoginRequest.code());
        body.add("redirect_uri", codeLoginRequest.redirectUri());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers());
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
        return parseTokenResponse(response);
    }

    public String getOauthIdpLoginLink(OauthLinkRequest oauthLinkRequest) {
        // 기본 인증 요청 URL 구성
        String idpUrl = props.getServerUrl() + "/realms/" + props.getRealm() + "/protocol/openid-connect/auth";

        // 쿼리 스트링 조합
        return UriComponentsBuilder.fromHttpUrl(idpUrl)
                .queryParam("client_id", props.getClientId())
                .queryParam("redirect_uri", oauthLinkRequest.redirectUri())
                .queryParam("response_type", "code")
                .queryParam("scope", oauthLinkRequest.scope())
                .queryParam("kc_idp_hint", oauthLinkRequest.idp())
                .build(true) // 인코딩
                .toUriString();
    }





    public void delete(UserDeleteRequest req) {
        String userId = findUserIdByUsername(req.username());
        if (userId == null) throw new RuntimeException("사용자 찾을 수 없음");

        String url = props.getServerUrl() + "/admin/realms/" + props.getRealm() + "/users/" + userId;
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getAdminAccessToken());

        HttpEntity<Void> request = new HttpEntity<>(headers);
        restTemplate.exchange(url, HttpMethod.DELETE, request, Void.class);
    }

    public void changeUserPassword(UserChangePasswordRequest changePasswordRequest) {
        String adminToken = getAdminAccessToken(); // 관리자의 access token

        String url = props.getServerUrl() + "/admin/realms/" + props.getRealm() + "/users/" + changePasswordRequest.userId() + "/reset-password";

        // 요청 바디 구성
        Map<String, Object> credentials = new HashMap<>();
        credentials.put("type", "password");
        credentials.put("value", changePasswordRequest.newPassword());
        credentials.put("temporary", false); // true로 설정 시, 다음 로그인 시 비밀번호 변경 요구

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(credentials, headers);
        restTemplate.put(url, request);
    }


    private HttpHeaders headers() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return headers;
    }

    private UserLoginResponse parseTokenResponse(ResponseEntity<Map> response) {
        if (response.getStatusCode().is2xxSuccessful()) {
            Map body = response.getBody();
            return new UserLoginResponse(
                (String) body.get("access_token"),
                (String) body.get("refresh_token"),
                ((Number) body.get("expires_in")).longValue()
            );
        }
        throw new RuntimeException("Keycloak 로그인 실패: " + response.getStatusCode());
    }

    private String getAdminAccessToken() {
        return signIn(new UserLoginRequest(props.getUsername(), props.getPassword())).accessToken();
    }

    private String findUserIdByUsername(String username) {
        String url = props.getServerUrl() + "/admin/realms/" + props.getRealm() + "/users?username=" + username;
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getAdminAccessToken());

        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<List> response = restTemplate.exchange(url, HttpMethod.GET, request, List.class);
        if (response.getBody() != null && !response.getBody().isEmpty()) {
            Map<String, Object> user = (Map<String, Object>) response.getBody().get(0);
            return (String) user.get("id");
        }
        return null;
    }
}
