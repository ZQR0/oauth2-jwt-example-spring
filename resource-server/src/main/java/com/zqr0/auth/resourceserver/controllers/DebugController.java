package com.zqr0.auth.resourceserver.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DebugController {

    @GetMapping(path = "/debug-resource")
    public String getMessage() {
        return "Resource server debug controller";
    }
}
