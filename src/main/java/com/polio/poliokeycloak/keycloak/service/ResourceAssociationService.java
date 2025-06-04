package com.polio.poliokeycloak.keycloak.service;

import com.polio.poliokeycloak.keycloak.client.KeycloakAdminClient;
import com.polio.poliokeycloak.keycloak.client.dto.PermissionRule;
import com.polio.poliokeycloak.keycloak.client.dto._IdentityInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ResourceAssociationService {
    private final KeycloakAdminClient keycloakAdminClient;
    public PermissionRule associateResource(PermissionRule permissionRule) {
        keycloakAdminClient.retrieveResourceIdentityPermission(permissionRule.getPermissionId())
                .stream()
                .map(_IdentityInfo::get_id)
                .map(keycloakAdminClient::findResourceById)
                .flatMap(Optional::stream)
                .findFirst()
                .ifPresent(permissionRule::setResource);

        return permissionRule;
    }
}
