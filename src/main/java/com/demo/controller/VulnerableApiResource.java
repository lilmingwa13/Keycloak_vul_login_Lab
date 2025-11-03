package com.demo.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 ** Dùng để tái hiện Lỗ hổng 6 (Sử dụng lại access token).
*/
@RestController
public class VulnerableApiResource {

    /**
     * Endpoint này trả về thông tin người dùng từ JWT.
     * Nó sẽ chấp nhận token ngay cả khi token đó được cấp cho một client khác,
     * vì cấu hình bảo mật đã cố tình bỏ qua việc kiểm tra 'audience'.
     */
    @GetMapping("/api/vulnerable/userinfo")
    public Map<String, Object> getVulnerableUserInfo(@AuthenticationPrincipal Jwt jwt) {
        System.out.println("=== API này thuộc về realm: realm-external ===");
        System.out.println("Token đến từ issuer: " + jwt.getIssuer());
        System.out.println("!!! Warning: API has Vul that sent successfully !!!");
        System.out.println("-> Token Audience (aud): " + jwt.getAudience());
        System.out.println("-> Token Subject (sub): " + jwt.getSubject());

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("subject", jwt.getSubject());
        userInfo.put("preferred_username", jwt.getClaimAsString("preferred_username"));
        userInfo.put("audience", jwt.getAudience());
        userInfo.put("message", "WARNING: This data was accessed via a vulnerable endpoint.");

        return userInfo;
    }
}
