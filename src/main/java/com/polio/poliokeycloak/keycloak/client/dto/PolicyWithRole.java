package com.polio.poliokeycloak.keycloak.client.dto;

import lombok.Data;

import java.util.List;
import java.util.Optional;

@Data
public class PolicyWithRole {
    private String id;
    private String name;
    private String description;
    private String type;
    private String logic;
    private String decisionStrategy;
    private List<RoleConfig> roles;
    public Optional<List<RoleConfig>> findRoles(){
        return Optional.ofNullable(this.roles);
    }
}
