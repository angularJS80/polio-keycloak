package com.polio.poliokeycloak.keycloak.client;

import com.polio.poliokeycloak.keycloak.client.dto.*;
import com.polio.poliokeycloak.keycloak.client.prop.KeycloakSecurityProperties;
import com.polio.poliokeycloak.keycloak.client.util.ScopeMaker;
import com.polio.poliokeycloak.keycloak.dto.ClientAuthMeta;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
@EnableConfigurationProperties(KeycloakSecurityProperties.class)
public class KeycloakAdminClient {

    private final RestTemplate restTemplate = new RestTemplate();
    private final KeycloakSecurityProperties props;
    private String CLIENT_UUID;
    private HttpEntity<?> HTTP_ENTITY;
    // 클라이언트 역할 ID → 역할명 캐싱
    private Map<String, String> cachedRoleIdNameMap;
    public static ClientAuthMeta CLIENT_AUTH_META;

    public String obtainAdminToken() {
        String tokenUrl = props.getServerUrl() + "/realms/" + props.getRealm() + "/protocol/openid-connect/token";

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", props.getClientId());
        params.add("client_secret", props.getClientSecret());
        params.add("username", props.getUsername());
        params.add("password", props.getPassword());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
        return (String) response.getBody().get("access_token");
    }

    private HttpEntity<?> makeAccessHeader() {
        String token = obtainAdminToken();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return new HttpEntity<>(headers);
    }

    private List<Resource> retrieveAllResources() {
        String resourceUrl = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/resource",
                props.getServerUrl(), props.getRealm(), CLIENT_UUID);

        List<Resource> resources =  restTemplate.exchange(
                resourceUrl,
                HttpMethod.GET,
                HTTP_ENTITY,
                new ParameterizedTypeReference<List<Resource>>() {
                }
        ).getBody();

        return associatedPermissionResources(resources);
    }

    private List<Permission> retrieveAllPermissions() {
        String permUrl = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/permission",
                props.getServerUrl(), props.getRealm(), CLIENT_UUID);

        return restTemplate.exchange(
                permUrl,
                HttpMethod.GET,
                HTTP_ENTITY,
                new ParameterizedTypeReference<List<Permission>>() {
                }
        ).getBody();
    }

    private List<Policy> retrieveAllPolicies() {
        String policyListUrl = String.format(
                "%s/admin/realms/%s/clients/%s/authz/resource-server/policy",
                props.getServerUrl(), props.getRealm(), CLIENT_UUID
        );
        return restTemplate.exchange(
                policyListUrl,
                HttpMethod.GET,
                HTTP_ENTITY,
                new ParameterizedTypeReference<List<Policy>>() {
                }
        ).getBody();
    }

    private List<Role> retrieveAllRoles() {
        String rolesUrl = String.format("%s/admin/realms/%s/clients/%s/roles",
                props.getServerUrl(), props.getRealm(), CLIENT_UUID);

        return restTemplate.exchange(
                rolesUrl,
                HttpMethod.GET,
                HTTP_ENTITY,
                new ParameterizedTypeReference<List<Role>>() {
                }
        ).getBody();
    }

    private void makeClientAuthMeta() {
        CLIENT_UUID = getClientUuid();
        CLIENT_AUTH_META = ClientAuthMeta.of(retrieveAllPermissions(),
                retrieveAllResources(),
                retrieveAllPolicies(),
                retrieveAllRoles()
        );
    }

    public List<_IdentityInfo> retrieveResourceIdentityPermission(String permissionId) {
        String resourceUrl = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/policy/%s/resources",
                props.getServerUrl(), props.getRealm(), CLIENT_UUID, permissionId);

        return restTemplate.exchange(
                resourceUrl,
                HttpMethod.GET,
                HTTP_ENTITY,
                new ParameterizedTypeReference<List<_IdentityInfo>>() {
                }
        ).getBody();
    }

    private Optional<List<Permission>> retrievePermissionsResourceId(String resourceId) {
        String resourceUrl = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/resource/%s/permissions",
                props.getServerUrl(), props.getRealm(), CLIENT_UUID, resourceId);

         List<Permission> permissions =  restTemplate.exchange(
                resourceUrl,
                HttpMethod.GET,
                HTTP_ENTITY,
                new ParameterizedTypeReference<List<Permission>>() {
                }
        ).getBody();
         return Optional.ofNullable(permissions);
    }

    public IdentityInfo createScope(String scopeName) {
        String scopeUrl = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/scope",
                props.getServerUrl(), props.getRealm(), CLIENT_UUID);

        Map<String, Object> scopeRequest = new HashMap<>();
        scopeRequest.put("name", scopeName);
        scopeRequest.put("displayName", "");
        scopeRequest.put("iconUri", "");

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(scopeRequest, HTTP_ENTITY.getHeaders());

        ResponseEntity<IdentityInfo> response = restTemplate.exchange(
                scopeUrl,
                HttpMethod.POST,
                request,
                IdentityInfo.class
        );

        return response.getBody();
    }


    public Optional<Map<String, Object>> requestRpt(String accessToken, String resourceId, String scopeName) {
        String tokenEndpoint = String.format("%s/realms/%s/protocol/openid-connect/token",
                props.getServerUrl(), props.getRealm());


        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBearerAuth(accessToken); // 기존 Access Token

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
        body.add("audience", props.getClientId());

        String permission = scopeName == null || scopeName.isEmpty()
                ? resourceId
                : resourceId + "#" + scopeName;
        body.add("permission", permission);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    tokenEndpoint,
                    HttpMethod.POST,
                    request,
                    new ParameterizedTypeReference<>() {}
            );
            return Optional.ofNullable(response.getBody());
        } catch (HttpClientErrorException | HttpServerErrorException ex) {
            log.warn("Failed to request RPT from Keycloak: {} - {}", ex.getStatusCode(), ex.getMessage());
        } catch (Exception ex) {
            log.error("Unexpected error while requesting RPT", ex);
        }

        return Optional.empty();
    }


    public List<Policy> retrievePolicyPermissionId(String permissionId) {
        String resourceUrl = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/policy/%s/associatedPolicies",
                props.getServerUrl(), props.getRealm(), CLIENT_UUID, permissionId);

        return restTemplate.exchange(
                resourceUrl,
                HttpMethod.GET,
                HTTP_ENTITY,
                new ParameterizedTypeReference<List<Policy>>() {
                }
        ).getBody();
    }

    public Optional<PolicyWithRole> findPolicyWithRoleByPolicyId(String policyId) {
        String resourceUrl = String.format("%s/admin/realms/%s/clients/%s/authz/resource-server/policy/role/%s",
                props.getServerUrl(), props.getRealm(), CLIENT_UUID, policyId);

        PolicyWithRole result = restTemplate.exchange(
                resourceUrl,
                HttpMethod.GET,
                HTTP_ENTITY,
                PolicyWithRole.class
        ).getBody();

        return Optional.ofNullable(result);
    }

    private String getClientUuid() {
        String clientsUrl = String.format("%s/admin/realms/%s/clients", props.getServerUrl(), props.getRealm());
        ResponseEntity<List> response = restTemplate.exchange(clientsUrl, HttpMethod.GET, HTTP_ENTITY, List.class);
        List<Map<String, Object>> clients = response.getBody();

        return clients.stream()
                .filter(c -> props.getClientId().equals(c.get("clientId")))
                .map(c -> (String) c.get("id"))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Client not found"));
    }

    @PostConstruct
    public void initialize() {
        HTTP_ENTITY = makeAccessHeader();
        makeClientAuthMeta();
    }

    public void refreshClientAuthMeta() {
        HTTP_ENTITY = makeAccessHeader();
        makeClientAuthMeta();
    }

    public List<Permission> getPermissions() {
        return CLIENT_AUTH_META.getPermissions();
    }

    public List<Resource> associatedPermissionResources(List<Resource> resources) {

        return resources.stream()
                .map(resource -> {
                    retrievePermissionsResourceId(resource.get_id())
                            .ifPresent(permissions -> {
                                if(permissions.size()>0){
                                    resource.setPermissions(permissions);
                                }
                            });
                    return resource;
                        }
                ).collect(Collectors.toList());

    }


    public Optional<Resource> findResourceById(String id) {
        return CLIENT_AUTH_META.findResource(id);
    }

    public Optional<Role> findRoleById(String id) {
        return CLIENT_AUTH_META.findRole(id);
    }
    public Optional<Policy> findPolicyByid(String id) {
        return CLIENT_AUTH_META.findPolicyById(id);
    }

    public Optional<Resource> findResourceByUri(String requestUri) {
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        return CLIENT_AUTH_META.getResources()
                .stream()
                .filter(resource -> resource.getUris().stream().filter(
                        uri->  antPathMatcher.match(uri,requestUri)
                ).findFirst().isPresent())
                .findFirst();

    }

    public String findOrCreateScope(String resourceId, HttpMethod httpMethod) {
        return  CLIENT_AUTH_META.findResource(resourceId)
                .map(resource -> {
                    String targetScope = ScopeMaker.makeScopeName(resource.getName(),httpMethod);

                    boolean hasScope = resource.findScope(targetScope)
                            .map(Resource.Scope::getName)
                            .isPresent();


                    if(!hasScope){
                        createScope(targetScope);
                    }
                    return targetScope;
                }).orElse(null);

    }

    public List<Resource> getResources() {
        return CLIENT_AUTH_META.getResources();
    }
}
