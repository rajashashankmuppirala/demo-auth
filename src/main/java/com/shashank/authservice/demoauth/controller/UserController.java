package com.shashank.authservice.demoauth.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;



@RestController
@RequestMapping("/okta")
public class UserController {

      @GetMapping("/login")
      public ResponseEntity<String> welcome(@AuthenticationPrincipal OAuth2User principal){
          System.out.println("test");
          return ResponseEntity.ok("Authenticated for "+ principal.getAttributes());
      }

    @GetMapping("/nonsecured")
    public ResponseEntity<String> nonsecured(){
        return ResponseEntity.ok("nonsecured endpoint");
    }

}
