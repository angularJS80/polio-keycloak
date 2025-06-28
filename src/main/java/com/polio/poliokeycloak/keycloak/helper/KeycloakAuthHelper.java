package com.polio.poliokeycloak.keycloak.helper;

import com.polio.poliokeycloak.keycloak.client.prop.KeycloakSecurityProperties;
import com.polio.poliokeycloak.keycloak.helper.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

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

    public void regist(UserRegisterRequest req) {
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
        restTemplate.postForEntity(url, request, Void.class);
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
