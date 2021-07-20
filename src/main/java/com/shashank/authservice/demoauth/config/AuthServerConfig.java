package com.shashank.authservice.demoauth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;


@Configuration
@EnableAuthorizationServer
@Slf4j
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    ClientDetailsService clientDetailsService;


    @Bean
    public TokenStore tokenStore() {
        log.info("tokenStore : {}");
        try {
            return new InMemoryTokenStore();
        }catch(Exception e) {
            log.error("Error occured in tokenStore {}"+e);
            throw e;
        }
    }


    @Bean
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices tokenService = new DefaultTokenServices();
        tokenService.setTokenStore(tokenStore());
        tokenService.setSupportRefreshToken(true);
        return tokenService;
    }
    @Bean
    DefaultOAuth2RequestFactory defaultOAuth2RequestFactory() {
        return new DefaultOAuth2RequestFactory(clientDetailsService);
    }

    @Bean
    public OAuth2AccessDeniedHandler oauthAccessDeniedHandler() {
        log.info("OAuth2AccessDeniedHandler : {}");
        try {
            return new OAuth2AccessDeniedHandler();
        }catch(Exception e) {
            log.error("Error occured in oauthAccessDeniedHandler {}"+e);
            throw e;
        }
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
        try {
            oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()").passwordEncoder(passwordEncoder);
        }catch(Exception e) {
            log.error("Error occured in checking token access {}"+e);
            throw e;
        }
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                .withClient("test").secret(passwordEncoder.encode("123456"))
                .scopes("read")
                .authorizedGrantTypes("password", "authorization_code", "refresh_token");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        try {
            endpoints.tokenStore(tokenStore()).authenticationManager(authenticationManager)
            .tokenServices(tokenServices());//.userDetailsService(userDetailsService);
            endpoints.exceptionTranslator(exception -> {
                if (exception instanceof OAuth2Exception) {
                    OAuth2Exception oAuth2Exception = (OAuth2Exception) exception;
                    return ResponseEntity
                            .status(oAuth2Exception.getHttpErrorCode())
                            .body(new OAuth2Exception(oAuth2Exception.getMessage()));
                } else {
                    log.error("Error occured in configuring AuthorizationserverEndPointsConfiguration {}"+exception);
                    throw exception;
                }
            });    	}catch(Exception e) {
            log.error("Error occured in configuring AuthorizationserverEndPointsConfiguration {}"+e);
            throw e;
        }
    }
}
