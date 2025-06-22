package com.polio.poliokeycloak.keycloak.helper.dto;

public record UserRegisterRequest(String username, String password, String email) {}