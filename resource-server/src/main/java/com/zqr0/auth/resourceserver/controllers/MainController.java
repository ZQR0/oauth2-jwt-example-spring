package com.zqr0.auth.resourceserver.controllers;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping(path = "/")
    public String getMessage(@AuthenticationPrincipal Jwt jwt) {
        return "Hello, " + jwt.getSubject();
    }

    @GetMapping(path = "/message")
    public String getSecretMessage() {
        return "Secret message";
    }

}
