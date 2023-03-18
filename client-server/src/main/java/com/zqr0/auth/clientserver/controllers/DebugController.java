package com.zqr0.auth.clientserver.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DebugController {

    @GetMapping(path = "/debug-client")
    public String getMessage() {
        return "Client server debug message";
    }
}
