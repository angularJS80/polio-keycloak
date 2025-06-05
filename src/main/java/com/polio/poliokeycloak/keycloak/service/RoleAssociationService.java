package com.polio.poliokeycloak.keycloak.service;

import com.polio.poliokeycloak.keycloak.client.KeycloakAdminClient;
import com.polio.poliokeycloak.keycloak.client.dto.PermissionRule;
import com.polio.poliokeycloak.keycloak.client.dto.PolicyWithRole;
import com.polio.poliokeycloak.keycloak.dto.RoleRule;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RoleAssociationService {
    private final KeycloakAdminClient keycloakAdminClient;
    public PermissionRule associateRole(PermissionRule permissionRule) {
        keycloakAdminClient.retrievePolicyPermissionId(permissionRule.getPermissionId()).forEach(policy -> {
            keycloakAdminClient.findPolicyByid(policy.getId())
                    .ifPresent(permissionRule::addPolicy);


            keycloakAdminClient.findPolicyWithRoleByPolicyId(policy.getId())
                    .flatMap(PolicyWithRole::findRoles)
                    .stream()
                    .flatMap(Collection::stream)
                    .map(roleConfig -> keycloakAdminClient.findRoleById(roleConfig.getId())
                            .map(role -> RoleRule.of(roleConfig, role.getName())))
                    .flatMap(Optional::stream)
                    .forEach(permissionRule::addRoleRule);
        });

        return permissionRule;
    }
}
