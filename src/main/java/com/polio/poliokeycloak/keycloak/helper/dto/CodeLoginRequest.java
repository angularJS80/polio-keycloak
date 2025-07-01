package com.polio.poliokeycloak.keycloak.helper.dto;

public record CodeLoginRequest(String code, String redirectUri) {}
