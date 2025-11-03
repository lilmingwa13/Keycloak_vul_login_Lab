package com.demo.config;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * MÔ PHỎNG LỖ HỔNG 6:
 *  - API này thuộc realm-external
 *  - Có kiểm tra issuer (iss) nhưng sai logic → token từ realm khác vẫn qua được
 */
@Configuration
public class VulnerableResourceServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain vulnerableApiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/vulnerable/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(vulnerableJwtDecoder()))
            );

        System.out.println("=== [LAB] API thuộc realm-external ===");
        System.out.println("=== [LAB] Có kiểm tra iss nhưng bị sai logic ===");

        return http.build();
    }

    /**
     * JwtDecoder có kiểm tra issuer nhưng cố tình bỏ qua điều kiện fail → lỗ hổng rõ ràng.
     */
    private JwtDecoder vulnerableJwtDecoder() {
        return token -> {
            try {
                // Decode payload JWT (không verify signature)
                String[] parts = token.split("\\.");
                String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
                String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));

                ObjectMapper om = new ObjectMapper();
                Map<String, Object> claims = om.readValue(payloadJson, Map.class);
                Map<String, Object> headers = om.readValue(headerJson, Map.class);

                String issuer = (String) claims.get("iss");

                Instant now = Instant.now();
                Instant exp = claims.containsKey("exp")
                        ? Instant.ofEpochSecond(((Number) claims.get("exp")).longValue()) : now.plusSeconds(3600);

                // LỖ HỔNG: kiểm tra nhưng không enforce (bỏ qua nếu sai)
                if (issuer != null) {
                    if (issuer.contains("realm-external")) {
                        System.out.println("Token issuer validddd: " + issuer);
                    } else {
                        System.out.println("Token issuer not found in realm external: " + issuer);
                        System.out.println("But dev has mistaked who doesn't check this bug!");
                    }
                } else {
                    System.out.println("Token issuer is null");
                }

                return new Jwt(token, now, exp, headers, claims);
            } catch (Exception e) {
                throw new JwtException("Decoding error in vulnerableJwtDecoder", e);
            }
        };
    }
}

