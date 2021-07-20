package com.shashank.authservice.demoauth.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.Serializable;
import java.util.*;


@RestController
@RequestMapping("/okta")
public class UserController {

    @Autowired
    private DefaultTokenServices tokenServices;

      @GetMapping("/login")
      public ResponseEntity<OAuth2AccessToken> welcome(@AuthenticationPrincipal OAuth2User principal){
          System.out.println("test");
          Map<String, String> requestParameters = new HashMap<String, String>();
          Map<String, Serializable> extensionProperties = new HashMap<String, Serializable>();

          boolean approved = true;
          Set<String> responseTypes = new HashSet<String>();
          responseTypes.add("code");

          List scopes = Arrays.asList("read");

          OAuth2Request oauth2Request = new OAuth2Request(requestParameters, "test", principal.getAuthorities(), approved, new HashSet<String>(scopes), new HashSet<String>(Arrays.asList("resourceIdTest")), null, responseTypes, extensionProperties);

          UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("test", "N/A", principal.getAuthorities());

          OAuth2Authentication auth = new OAuth2Authentication(oauth2Request, authenticationToken);

          OAuth2AccessToken token = tokenServices.createAccessToken(auth);

          return ResponseEntity.ok(token);

      }

    @GetMapping("/nonsecured")
    public ResponseEntity<String> nonsecured(){
        return ResponseEntity.ok("nonsecured endpoint");
    }

}
