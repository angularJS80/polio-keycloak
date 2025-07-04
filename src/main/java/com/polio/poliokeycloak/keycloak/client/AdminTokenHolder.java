package com.polio.poliokeycloak.keycloak.client;

public class AdminTokenHolder {
    private String accessToken;
    private String refreshToken;
    private long expiresAt; // milliseconds

    public synchronized boolean isExpiringSoon() {
        long currentTime = System.currentTimeMillis();
        return expiresAt - currentTime <= 60000; // 1분 이하 남았는가?
    }

    public synchronized void update(String accessToken, String refreshToken, int expiresInSeconds) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresAt = System.currentTimeMillis() + (expiresInSeconds * 1000L);
    }

    public synchronized String getAccessToken() {
        return this.accessToken;
    }

    public synchronized String getRefreshToken() {
        return this.refreshToken;
    }
}
