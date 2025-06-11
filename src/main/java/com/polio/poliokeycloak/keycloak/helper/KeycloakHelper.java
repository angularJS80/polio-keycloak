package com.polio.poliokeycloak.keycloak.helper;

import com.polio.poliokeycloak.keycloak.client.KeycloakAdminClient;
import com.polio.poliokeycloak.keycloak.client.dto.Resource;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;


@Component
@RequiredArgsConstructor
public class KeycloakHelper {
    private final KeycloakAdminClient keycloakAdminClient;

    public List<String> hasPermissionsPatterns(){
        return hasPermissionsResources()
                .stream()
                .flatMap(resource -> resource.getUris().stream())
                .collect(Collectors.toList());
    }

    public List<String> hasNoPermissionsPatterns(){
        return hasNoPermissionsResources()
                .stream()
                .flatMap(resource -> resource.getUris().stream())
                .collect(Collectors.toList());
    }

    public AuthorizationDecision decide(HttpMethod httpMethod, Authentication authentication, String uri) {
        return new AuthorizationDecision(umaCheck(httpMethod, authentication, uri));
    }

    private boolean umaCheck(HttpMethod httpMethod, Authentication authentication, String uri){

        boolean isValidUmaTicket =false;
        if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            String tokenValue = jwtAuthenticationToken.getToken().getTokenValue();
            isValidUmaTicket = requestUmaTicket(tokenValue,
                    uri,httpMethod);
        }

        return isValidUmaTicket;
    }

    private boolean requestUmaTicket(String accessToken, String uri, HttpMethod httpMethod){
        // 접근한 메소드
        return keycloakAdminClient.findResourceByUri(uri)
                .map(resource -> {
                    // 스코프를 찾아서 있으면 요청하고, 없으면 만들어서라도 리턴한다.
                    String scopeName = keycloakAdminClient.findOrCreateScope(resource.get_id(),httpMethod);
                    return keycloakAdminClient.requestRpt(accessToken,resource.get_id(),scopeName)
                            .map(rptBody-> rptBody != null && rptBody.containsKey("access_token")
                            ).orElse(false);

                }).orElse(false);

    }



    private List<Resource> getResources() {
        return keycloakAdminClient.getResources();
    }


    private List<Resource> hasNoPermissionsResources(){
        return getResources()
                .stream()
                .filter(Resource::emptyPermissions)
                .collect(Collectors.toList());
    }

    private List<Resource> hasPermissionsResources(){
        return getResources()
                .stream()
                .filter(Resource::hasPermissions)
                .collect(Collectors.toList());
    }

}
