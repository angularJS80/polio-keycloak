package com.polio.poliokeycloak.keycloak.helper.dto;

public record OauthLinkRequest(String idp, String redirectUri, String scope) {}
