package com.polio.poliokeycloak.keycloak.client.dto;

import lombok.Data;

import java.util.Map;

@Data
public class Role extends IdentityInfo {
    private String description;
    private boolean composite;
    private boolean clientRole;
    private String containerId;
    private Map<String, Object> attributes;
}