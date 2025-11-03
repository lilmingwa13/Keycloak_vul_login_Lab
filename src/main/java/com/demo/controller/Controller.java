package com.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

    // @GetMapping("/web/user")
    // public String userAccess() {
    //     return "Hello USER - You can access this page.";
    // }

    // @GetMapping("/web/admin")
    // public String adminAccess() {
    //     return "Hello ADMIN - You can access this page.";
    // }

    @GetMapping("/public/home")
    public String home() {
        return "Welcome! Please login with Keycloak.";
    }

    // @GetMapping("/dashboard")
    // public String dashboard() {
    //     return "dashboard";
    // }
    
}
