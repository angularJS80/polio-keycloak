package com.polio.poliokeycloak.keycloak.client.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class IdentityInfo {
    private String id;
    private String name;
}
