package com.polio.poliokeycloak;

import com.polio.poliokeycloak.keycloak.helper.AccessTokenManager;
import com.polio.poliokeycloak.keycloak.helper.KeycloakAuthHelper;
import com.polio.poliokeycloak.keycloak.helper.dto.UserDeleteRequest;
import com.polio.poliokeycloak.keycloak.helper.dto.UserLoginRequest;
import com.polio.poliokeycloak.keycloak.helper.dto.UserLoginResponse;
import com.polio.poliokeycloak.keycloak.helper.dto.UserRegisterRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class KeycloakTokenTest {

    @Autowired
    private KeycloakAuthHelper keycloakAuthHelper;

    @Autowired
    private AccessTokenManager accessTokenManager;


    //@PostConstruct
    public void init() {
        // 초기 로그인 처리, username과 password를 사용하여 토큰 갱신
        UserLoginRequest request = new UserLoginRequest("tempuser_df7a8318-8238-4029-938b-58de880e6435", "1234");
        accessTokenManager.login(request);
    }

    //@Test
    void testUserLogin() {
        String username = "tempuser_" + UUID.randomUUID();
        String password = "TempPass123!";
        String email = username + "@test.com";

        UserRegisterRequest registerRequest = new UserRegisterRequest(username, password, email);
        keycloakAuthHelper.regist(registerRequest);

        UserLoginRequest request = new UserLoginRequest(username, password);
        UserLoginResponse response = keycloakAuthHelper.auth(request);

        assertNotNull(response.accessToken());
        assertNotNull(response.refreshToken());
        assertTrue(response.expiresIn() > 0);
        System.out.println("AccessToken: " + response.accessToken());
    }



    // @Test
    void testRegisterAndDeleteUser() {
        String username = "tempuser_" + UUID.randomUUID();
        String password = "TempPass123!";
        String email = username + "@test.com";

        UserRegisterRequest registerRequest = new UserRegisterRequest(username, password, email);
        keycloakAuthHelper.regist(registerRequest);
        UserLoginRequest request = new UserLoginRequest(username, password);
        UserLoginResponse response = keycloakAuthHelper.auth(request);
        UserDeleteRequest deleteRequest = new UserDeleteRequest(username);
        keycloakAuthHelper.delete(deleteRequest);
    }

    //@Test
    void login(){
        UserLoginRequest request = new UserLoginRequest("tempuser_df7a8318-8238-4029-938b-58de880e6435", "1234");
        UserLoginResponse response = keycloakAuthHelper.auth(request);
        System.out.println("Refreshed Token: " + response.refreshToken());
    }

    //@Test
    void continueAccessTestLoop() throws InterruptedException {
        System.out.println("Start lock mode");
        int tremOfSeconds = 10;
        int refreshCount = 30;
        int callCount = 10;

        for(int i=0;i<refreshCount; i++){
            try {
                TimeUnit.SECONDS.sleep(tremOfSeconds); // 5분 대기
                System.out.println("after Seconds"+tremOfSeconds*(i+1));
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            RefreshTest(true,callCount);
        }

        System.out.println("Start lock no lock");
        //modeTest(false,1000);
    }


    public void RefreshTest(boolean mode, int numberOfCalls) throws InterruptedException {
        // CountDownLatch를 사용하여 다회 호출 테스트

        CountDownLatch readyLatch = new CountDownLatch(numberOfCalls);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(numberOfCalls);

        for (int i = 0; i < numberOfCalls; i++) {
            new Thread(() -> {
                readyLatch.countDown(); // 준비 완료
                try {
                    startLatch.await(); // 모든 스레드가 준비될 때까지 대기
                    String token = accessTokenManager.getAccessToken();
                    assertNotNull(token, "Token should not be null");
                    System.out.println("Thread : "+token.length()+Thread.currentThread().getName()+"Access Token: " + token.substring(1480,1486));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown(); // 완료 알림
                }
            }).start();
        }

// 모든 스레드가 준비될 때까지 대기
        readyLatch.await();

// 모든 스레드에게 동시에 시작 신호
        startLatch.countDown();

// 모든 스레드가 완료될 때까지 대기
        doneLatch.await();

    }

}
