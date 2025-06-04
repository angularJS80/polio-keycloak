package com.polio.poliokeycloak.keycloak.service;

import com.polio.poliokeycloak.keycloak.client.KeycloakAdminClient;
import com.polio.poliokeycloak.keycloak.client.dto.PermissionRule;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;


@Service
@RequiredArgsConstructor
public class KeycloakPermissionService {
    private final KeycloakAdminClient keycloakAdminClient;
    private final ResourceAssociationService resourceAssociationService;
    private final RoleAssociationService roleAssociationService;

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
