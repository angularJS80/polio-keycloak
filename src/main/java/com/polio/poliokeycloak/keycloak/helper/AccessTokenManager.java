package com.polio.poliokeycloak.keycloak.helper;

import com.polio.poliokeycloak.keycloak.helper.dto.UserLoginRequest;
import com.polio.poliokeycloak.keycloak.helper.dto.UserLoginResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@RequiredArgsConstructor
@Service
public class AccessTokenManager {

    private final KeycloakAuthHelper keycloakAuthHelper;  // 이미 준비된 KeycloakAuthHelper
    private final TokenStore tokenStore;

    private final AtomicBoolean lock = new AtomicBoolean(false);
    private final AtomicReference<String> lockedBy = new AtomicReference<>(null);
    private volatile CountDownLatch updateDone = new CountDownLatch(1); // 업데이트 완료 신호

    public String getAccessToken() {
        if (tokenStore.isExpired()) {
            boolean acquired = lock.compareAndSet(false, true);

            if (acquired) {
                CountDownLatch newLatch = new CountDownLatch(1);
                updateDone = newLatch;
                lockedBy.set(Thread.currentThread().getName());
                try {
                    refreshAccessToken();
                } finally {
                    newLatch.countDown(); // signal done
                    lock.set(false); // release the lock
                }

            } else {
                try {
                    updateDone.await(); // 여기서 업데이트가 끝날 때까지 기다림
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        return tokenStore.getAccessToken(); // 갱신 완료된 accessToken 반환
    }

    public void login(UserLoginRequest request) {
        UserLoginResponse refreshed = keycloakAuthHelper.signIn(request);
        if (refreshed != null && refreshed.accessToken() != null) {
            this.tokenStore.update(refreshed);
        } else {
            throw new RuntimeException("Initial login failed");
        }
    }


    private void refreshAccessToken() {
        // KeycloakAuthHelper의 authByRefresh() 메서드를 이용해 토큰을 갱신
        UserLoginResponse refreshed = keycloakAuthHelper.refresh(tokenStore.getRefreshToken());

        if (refreshed != null && refreshed.accessToken() != null) {
            this.tokenStore.update(refreshed);
        } else {
            throw new RuntimeException("Failed to refresh access token");
        }
    }

}
