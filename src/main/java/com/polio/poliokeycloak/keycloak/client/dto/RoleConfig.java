package com.polio.poliokeycloak.keycloak.client.dto;

import lombok.Data;

@Data
public class RoleConfig {
    private String id;
    private boolean required;
}
