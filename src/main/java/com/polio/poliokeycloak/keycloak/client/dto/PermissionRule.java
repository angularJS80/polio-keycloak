package com.polio.poliokeycloak.keycloak.client.dto;

import com.polio.poliokeycloak.keycloak.dto.RoleRule;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Data
public class PermissionRule {
    String permissionId;
    Resource resource;
    List<Policy> policys = new ArrayList<>();
    List<RoleRule> roleRules = new ArrayList<>();


    public PermissionRule(Permission permission) {
        this.permissionId = permission.getId();
    }

    public static PermissionRule of(Permission permission) {
        return new PermissionRule(permission);
    }

    public void setResource(Resource resource) {
        this.resource = resource;
    }

    public void addPolicy(Policy policy) {
        this.policys.add(policy);
    }


    public void addRoleRule(RoleRule roleRule) {
        this.roleRules.add(roleRule);
    }

    public Optional<Resource> findResource(){
        return Optional.ofNullable(this.resource);
    }
}

