package com.demo.controller;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.ui.Model;


@Controller 
public class ViewController {

    @GetMapping("/dashboard")
    public String dashboard(HttpServletRequest request, Model model) {
        String currentApp = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("currentApp".equals(cookie.getName())) {
                    currentApp = cookie.getValue();
                    break;
                }
            }
        }
        model.addAttribute("currentApp", currentApp);

        model.addAttribute("isExternalClient", "external-client".equals(currentApp));

        model.addAttribute("isAttackerSameRealm", "attacker-client-same-realm".equals(currentApp));

        System.out.println("CurrentApp cookie = " + currentApp);
        return "dashboard"; 
    }

    @GetMapping("/web/user")
    public String userAccess() {
        return "scoreboard";
    }

    @GetMapping("/web/admin")
    public String adminAccess() {
        return "personal";
    }

    @GetMapping("/")
    public String homePage() {
        return "index"; 
    }
}