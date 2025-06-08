package com.polio.poliokeycloak.keycloak.client.util;

import org.springframework.http.HttpMethod;

import static org.springframework.http.HttpMethod.*;

public class ScopeMaker {

    public static String makeScopeName(String resourceName, HttpMethod httpMethod) {
        return resourceName+"."+ resolveScope(httpMethod);

    }

    public static String resolveScope(HttpMethod method) {
        if (method == null) return "execute";

        if (method.equals(GET) || method.equals(HEAD) || method.equals(OPTIONS)) {
            return "read";
        } else if (method.equals(POST)) {
            return "create";
        } else if (method.equals(PUT)) {
            return "update";
        } else if (method.equals(PATCH)) {
            return "patch";
        } else if (method.equals(DELETE)) {
            return "delete";
        }
        return "execute";
    }
}
