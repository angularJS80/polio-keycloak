package com.polio.poliokeycloak.keycloak.helper.dto;

public record UserLoginResponse(String accessToken, String refreshToken, long expiresIn) {}