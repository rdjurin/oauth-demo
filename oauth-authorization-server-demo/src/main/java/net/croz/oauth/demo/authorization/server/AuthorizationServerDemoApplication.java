package net.croz.oauth.demo.authorization.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@SpringBootApplication
public class AuthorizationServerDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerDemoApplication.class, args);
    }

}
