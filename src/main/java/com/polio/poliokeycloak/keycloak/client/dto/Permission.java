package com.polio.poliokeycloak.keycloak.client.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Permission extends IdentityInfo {

    private String description;
    private String type;
    private String logic;
    private String decisionStrategy;
    private String resourceType;
}
