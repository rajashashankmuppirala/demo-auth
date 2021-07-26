package com.shashank.authservice.demoauth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OktaConfig {

    @Value("${spring.security.oauth2.client.provider.okta.tokenUri}")
    String tokenUri;

    @Value("${spring.security.oauth2.client.registration.okta.clientId}")
    String clientId;

    @Value("${spring.security.oauth2.client.registration.okta.clientSecret}")
    String clientSecret;
}
