package com.polio.poliokeycloak.keycloak.service;

import com.polio.poliokeycloak.keycloak.client.KeycloakAdminClient;
import com.polio.poliokeycloak.keycloak.client.dto.PermissionRule;
import com.polio.poliokeycloak.keycloak.client.dto.Resource;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import java.util.List;
import java.util.stream.Collectors;


@Service
@RequiredArgsConstructor
public class KeycloakPermissionService {
    private final KeycloakAdminClient keycloakAdminClient;
    private final ResourceAssociationService resourceAssociationService;
    private final RoleAssociationService roleAssociationService;



    public boolean umaCheck(AuthorizationContext authorizationContext, Authentication authentication, String uri){
        authorizationContext.getExchange().getRequest().getMethod();

        boolean isValidUmaTicket =false;
        if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            String tokenValue = jwtAuthenticationToken.getToken().getTokenValue();
            isValidUmaTicket = requestUmaTicket(tokenValue,
                    uri,authorizationContext.getExchange().getRequest().getMethod());

        }

        return isValidUmaTicket;
    }

    public boolean requestUmaTicket(String accessToken, String uri, HttpMethod httpMethod){
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

    public List<PermissionRule> getPermissionRules() {
        return keycloakAdminClient.getPermissions()
                .stream()
                .map(PermissionRule::of)
                .map(this::buildPermissionRuleWithAssociations)
                .collect(Collectors.toList());
    }

    private PermissionRule buildPermissionRuleWithAssociations(PermissionRule permissionRule) {
        resourceAssociationService.associateResource(permissionRule);
        roleAssociationService.associateRole(permissionRule);
        return permissionRule;
    }


    public List<Resource> getResources() {
        return keycloakAdminClient.getResources();
    }

    public List<Resource> hasNoPermissionsResources(){
        return getResources()
                .stream()
                .filter(Resource::emptyPermissions)
                .collect(Collectors.toList());
    }

    public boolean isNoPermission(String targetUrl) {
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        return hasNoPermissionsResources().stream()
                .anyMatch(resource ->
                      resource.getUris()
                            .stream()
                            .anyMatch(uri-> antPathMatcher.match(uri,targetUrl))


                );
    }


}
