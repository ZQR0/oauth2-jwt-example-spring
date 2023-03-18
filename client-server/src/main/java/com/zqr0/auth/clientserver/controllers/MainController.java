package com.zqr0.auth.clientserver.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
public class MainController {

    @Autowired
    private WebClient webClient;

    @GetMapping(value = "get-message")
    public String getAuthMessage() {
        return "Authorized";
    }
}
