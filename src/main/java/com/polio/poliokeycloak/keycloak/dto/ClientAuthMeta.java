package com.polio.poliokeycloak.keycloak.dto;

import com.polio.poliokeycloak.keycloak.client.dto.Permission;
import com.polio.poliokeycloak.keycloak.client.dto.Policy;
import com.polio.poliokeycloak.keycloak.client.dto.Resource;
import com.polio.poliokeycloak.keycloak.client.dto.Role;
import lombok.Data;

import java.util.List;
import java.util.Optional;

@Data
public class ClientAuthMeta {
    private final List<Resource> resources;
    private final List<Permission> permissions;
    private final List<Role> roles;
    private final List<Policy> policies;

    private ClientAuthMeta(List<Permission> permissions, List<Resource> resources, List<Policy> policies, List<Role> roles) {
        this.permissions = permissions;
        this.resources = resources;
        this.policies = policies;
        this.roles = roles;
    }

    public static ClientAuthMeta of(List<Permission> permissions, List<Resource> resources, List<Policy> policies, List<Role> roles) {
        return new ClientAuthMeta(permissions, resources, policies, roles);
    }

    public Optional<Resource> findResource(String id) {
        return resources.stream()
                .filter(resource -> resource.get_id().equals(id))
                .findFirst();
    }

    public Optional<Role> findRole(String roleid) {
        return this.roles.stream()
                .filter(role -> role.getId().equals(roleid))
                .findFirst();
    }

    public Optional<Policy> findPolicyById(String id) {
        return this.policies.stream()
                .filter(policy -> policy.getId().equals(id))
                .findFirst();
    }
}
