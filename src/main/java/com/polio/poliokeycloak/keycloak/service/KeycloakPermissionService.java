package com.polio.poliokeycloak.keycloak.service;

import com.polio.poliokeycloak.keycloak.client.KeycloakAdminClient;
import com.polio.poliokeycloak.keycloak.client.dto.PermissionRule;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;


@Service
@RequiredArgsConstructor
public class KeycloakPermissionService {
    private final KeycloakAdminClient keycloakAdminClient;
    private final ResourceAssociationService resourceAssociationService;
    private final RoleAssociationService roleAssociationService;


    public boolean requestUmaTicket(String accessToken, String uri, HttpMethod httpMethod){
        return keycloakAdminClient.findResourceByUri(uri)
                .map(resource -> {
                    // 스코프를 찾아서 있으면 요청하고, 없으면 만들어서라도 리턴한다.
                    String scopeName = keycloakAdminClient.findOrCreateScope(resource.get_id(),httpMethod);
                    return keycloakAdminClient.requestRpt(accessToken,resource.get_id(),scopeName)
                            .map(rptBody-> rptBody != null && rptBody.containsKey("access_token")
                            ).orElse(false);

                }).orElse(false);

    }

    public List<PermissionRule> getPermissionRules() {
        return keycloakAdminClient.getPermissions()
                .stream()
                .map(PermissionRule::of)
                .map(this::buildPermissionRuleWithAssociations)
                .collect(Collectors.toList());
    }

    private PermissionRule buildPermissionRuleWithAssociations(PermissionRule permissionRule) {
        resourceAssociationService.associateResource(permissionRule);
        roleAssociationService.associateRole(permissionRule);
        return permissionRule;
    }








}
