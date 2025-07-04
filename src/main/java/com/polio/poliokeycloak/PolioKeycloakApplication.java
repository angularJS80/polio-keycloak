package com.polio.poliokeycloak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PolioKeycloakApplication {

    public static void main(String[] args) {
        SpringApplication.run(PolioKeycloakApplication.class, args);
    }

}
