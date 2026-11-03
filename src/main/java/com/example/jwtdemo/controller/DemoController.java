package com.example.jwtdemo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class DemoController {

    @GetMapping("/api/me")
    public Map<String, Object> me(Authentication auth) {
        return Map.of("username", auth.getName(),
                      "roles", auth.getAuthorities().stream().map(Object::toString).toList());
    }

    @GetMapping("/api/admin/hello")
    public Map<String, String> admin(Authentication auth) {
        return Map.of("message", "Hello admin " + auth.getName());
    }
}
