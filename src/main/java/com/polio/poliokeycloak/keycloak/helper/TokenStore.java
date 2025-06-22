package com.polio.poliokeycloak.keycloak.helper;

import com.polio.poliokeycloak.keycloak.helper.dto.UserLoginResponse;
import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
public class TokenStore {
    private String refreshToken;
    private String accessToken;
    private long expiresAt;

    public void update(UserLoginResponse refreshed) {
        // 밀리초 단위로 설정
        this.expiresAt = System.currentTimeMillis() + (refreshed.expiresIn() - 30) * 1000L;
        this.accessToken = refreshed.accessToken();
        this.refreshToken = refreshed.refreshToken();
    }

    public synchronized boolean isExpired() {

        return this.accessToken == null || System.currentTimeMillis() >= this.expiresAt;
    }
}
