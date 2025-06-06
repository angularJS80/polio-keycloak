package com.polio.poliokeycloak.keycloak.client.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Optional;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Resource extends _IdentityInfo {

    private List<String> uris;
    private List<Scope> scopes;

    public Optional<Scope> findScope(String targetScope) {
        return findScopes()
                .orElse(List.of()) // Optional을 벗겨서 빈 리스트로 fallback
                .stream()
                .filter(scope -> scope.getName().equals(targetScope))
                .findFirst();
    }

    public Optional<List<Scope>> findScopes(){
        return Optional.ofNullable(this.scopes);
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Scope {
        private String id;
        private String name;
        private String iconUri;
    }
}
