package com.polio.poliokeycloak.keycloak.helper.dto;

public record ExchangeUserRequest( String requestedSubject, String audience, String scope) {}