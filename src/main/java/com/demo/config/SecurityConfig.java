
// @Configuration
// @EnableWebSecurity
// @EnableMethodSecurity // Bật tính năng bảo mật ở cấp độ phương thức (ví dụ: @PreAuthorize)
// public class SecurityConfig {

//     @Bean
//     @Order(1) // Ưu tiên chạy trước
//     public SecurityFilterChain publicEndpoints(HttpSecurity http) throws Exception {
//         http
//             .securityMatcher("/public/**", "/", "/index.html", "/*.js", "/*.css") // chỉ áp dụng cho /public/**
//             .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
//             .csrf(csrf -> csrf.disable());
//         return http.build();
//     }

//     @Bean
//     @Order(2) // Ưu tiên chạy sau
//     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//         return http
//                 // 1. Tắt CSRF vì chúng ta dùng JWT (stateless)
//                 .csrf(csrf -> csrf.disable())

//                 // 2. Cấu hình quy tắc phân quyền cho các request
//                 .authorizeHttpRequests(authorize -> authorize
//                         .requestMatchers("/web/user/**").hasRole("USER")
//                         .requestMatchers("/web/admin/**").hasRole("ADMIN")
//                         // .requestMatchers("/public/**").permitAll() // Cho phép truy cập công khai
//                         // Tất cả các request khác đều cần phải xác thực
//                         .anyRequest().authenticated()
//                 )

//                 // 3. Cấu hình server như một OAuth2 Resource Server để xác thực JWT
//                 .oauth2ResourceServer(oauth2 -> oauth2
//                         .jwt(jwt -> jwt
//                                 // Sử dụng bộ chuyển đổi JWT tùy chỉnh của chúng ta
//                                 .jwtAuthenticationConverter(jwtAuthenticationConverter())
//                         )
//                 )

//                 // 4. Cấu hình chính sách quản lý session là STATELESS (không tạo session)
//                 .sessionManagement(session -> session
//                         .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                 )

//                 .build();
//     }

//     // Bean này có nhiệm vụ chuyển đổi các "claim" trong JWT thành các quyền (Authorities)
//     // và thông tin người dùng (Principal) mà Spring Security có thể hiểu.
//     @Bean
//     public JwtAuthenticationConverter jwtAuthenticationConverter() {
//         // Tạo một bộ chuyển đổi để đọc các quyền (roles) từ JWT
//         JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
//         // Chỉ cho Spring biết cần đọc quyền từ claim nào trong token của Keycloak
//         // Thường là 'realm_access' (cho vai trò toàn cục) hoặc 'resource_access' (cho vai trò của client)
//         grantedAuthoritiesConverter.setAuthoritiesClaimName("realm_access");
//         // Thêm tiền tố "ROLE_" mặc định của Spring Security vào các quyền đọc được
//         // Ví dụ: role "USER" trong Keycloak sẽ thành "ROLE_USER" trong Spring
//         grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

//         // Tạo bộ chuyển đổi JWT chính
//         JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
//         // Gán bộ chuyển đổi quyền ở trên
//         jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
//         // Chỉ cho Spring biết cần lấy claim nào làm tên người dùng (Principal name)
//         // 'preferred_username' là một lựa chọn phổ biến trong Keycloak
//         jwtAuthenticationConverter.setPrincipalClaimName("preferred_username");

//         return jwtAuthenticationConverter;
//     }
// }

package com.demo.config;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

// @Configuration
// public class SecurityConfig {

//     /**
//      * Security cho API (/web/**) -> Resource Server (JWT)
//      * Không dùng session, validate Bearer token
//      */
//     @Bean
//     @Order(1)
//     public SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
//         http
//             .securityMatcher("/web/**") // Áp dụng cho API
//             .csrf(csrf -> csrf.disable())
//             .authorizeHttpRequests(auth -> auth
//                 .requestMatchers("/web/user/**").hasRole("USER")
//                 .requestMatchers("/web/admin/**").hasRole("ADMIN")
//                 .anyRequest().authenticated()
//             )
//             .oauth2ResourceServer(oauth2 -> oauth2
//                 .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
//             )
//             .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

//         return http.build();
//     }

//     /**
//      * Security cho UI (browser login) -> Authorization Code Flow
//      * Dùng session, login qua Keycloak
//      */
//     @Bean
//     @Order(2)
//     public SecurityFilterChain uiSecurity(HttpSecurity http) throws Exception {
//         // 1. Tạo một request handler
//         // HttpSessionCsrfTokenRepository tokenRepository = new HttpSessionCsrfTokenRepository();
        
//         // // 2. Chỉ định tên header mà server sẽ tìm kiếm.
//         // tokenRepository.setHeaderName("X-Csrf-Token");

//         http
//             .authorizeHttpRequests(auth -> auth
//                 .requestMatchers("/", "/public/**").permitAll()
//                 .anyRequest().authenticated()
//             )
//             .oauth2Login(oauth2 -> oauth2
//                 .defaultSuccessUrl("/web/user", true) // redirect cố định sau khi login thành công
//             )
//             // .csrf(csrf -> 
//             //     csrf.csrfTokenRepository(tokenRepository)
//             // );

//              .csrf(csrf -> 
//              csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//             )
//             .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

//         return http.build();
//     }

//     /**
//      * Chuyển đổi JWT claim thành GrantedAuthorities
//      */
//     @Bean
//     public JwtAuthenticationConverter jwtAuthenticationConverter() {
//         JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
//         // Keycloak lưu role ở "realm_access.roles"
//         grantedAuthoritiesConverter.setAuthoritiesClaimName("realm_access.roles");
//         grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

//         JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
//         jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
//         // Dùng 'preferred_username' làm Principal
//         jwtAuthenticationConverter.setPrincipalClaimName("preferred_username");

//         return jwtAuthenticationConverter;
//     }
// }

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

//     @Bean
//     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//         http
//             // 1. Định nghĩa quy tắc cho tất cả các request
//             .authorizeHttpRequests(authorize -> authorize
//                 // Cho phép các trang public và trang đăng ký
//                 .requestMatchers("/", "/public/**", "/register").permitAll()
//                 // Yêu cầu role 'USER' cho /web/user
//                 .requestMatchers("/web/user/**").hasRole("USER")
//                 // Yêu cầu role 'ADMIN' cho /web/admin
//                 .requestMatchers("/web/admin/**").hasRole("ADMIN")
//                 // Tất cả các request khác đều cần đăng nhập
//                 .anyRequest().authenticated()
//             )
//             // 2. Cấu hình đăng nhập qua trình duyệt (UI)
//             .oauth2Login(oauth2 -> oauth2
//                 // Chuyển hướng đến /web/user sau khi đăng nhập thành công
//                 .defaultSuccessUrl("/web/user", true)
//             )
//             // 3. Cấu hình xác thực token cho API
//             .oauth2ResourceServer(oauth2 -> oauth2
//                 .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
//             );
//             // Bỏ .sessionManagement() để dùng session mặc định cho oauth2Login

//         return http.build();
//     }

//     // Bean này đã được sửa lại để đọc role từ Keycloak một cách chính xác
//     @Bean
//     public JwtAuthenticationConverter jwtAuthenticationConverter() {
//         JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
//         // Bộ chuyển đổi này sẽ trích xuất các quyền từ token
//         jwtConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
//             // Lấy object "realm_access" từ trong token
//             Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");

//             if (realmAccess == null || realmAccess.isEmpty()) {
//                 return Collections.emptyList(); // Trả về danh sách rỗng nếu không có
//             }

//             // Lấy danh sách các role từ trong "realm_access"
//             Collection<String> roles = (Collection<String>) realmAccess.get("roles");

//             // Chuyển đổi mỗi role thành một đối tượng GrantedAuthority mà Spring Security hiểu
//             return roles.stream()
//                     .map(roleName -> "ROLE_" + roleName.toUpperCase()) // Thêm tiền tố ROLE_ theo chuẩn của Spring
//                     .map(SimpleGrantedAuthority::new)
//                     .collect(Collectors.toList());
//         });
//         return jwtConverter;
//     }
// }


// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

//     private final ClientRegistrationRepository clientRegistrationRepository;

//     public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository) {
//         this.clientRegistrationRepository = clientRegistrationRepository;
//     }

//     @Bean
//     @Order(2)
//     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//         http
//             .authorizeHttpRequests(authorize -> authorize
//                 .requestMatchers("/vulnerable/**").permitAll()
//                 .requestMatchers("/", "/public/**", "/register").permitAll()
//                 .requestMatchers("/dashboard").authenticated()
//                 .requestMatchers("/web/user/**").hasRole("USER")
//                 .requestMatchers("/web/admin/**").hasRole("ADMIN")
//                 .anyRequest().authenticated()
//             )
//             .oauth2Login(oauth2 -> oauth2
//                 .defaultSuccessUrl("/dashboard", true)
//                 // *** THÊM DÒNG NÀY ĐỂ KẾT NỐI VỚI MAPPER MỚI ***
//                 .userInfoEndpoint(userInfo -> userInfo.userAuthoritiesMapper(userAuthoritiesMapper()))
//             )

//             // === LOGOUT Ở ĐÂY ===
//             // .logout(logout -> {
//             //     // Chỉ định URL sẽ kích hoạt quá trình logout
//             //     logout.logoutSuccessUrl("/"); 
//             //     // Hủy session của ứng dụng
//             //     logout.invalidateHttpSession(true); 
//             //     // Xóa cookie JSESSIONID
//             //     logout.deleteCookies("JSESSIONID"); 
//             // })
//             .logout(logout -> logout
//                 .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository))
//             );
//             // ===================================

//             // .oauth2ResourceServer(oauth2 -> oauth2
//             //     .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
//             // );

//         return http.build();
//     }

//     //ADD
//     @Bean
//     public LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
//         OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
//             new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);

//         // URL quay về sau khi logout
//         oidcLogoutSuccessHandler.setPostLogoutRedirectUri("http://localhost:8080/");
//         return oidcLogoutSuccessHandler;
//     }

    
//     // Bean này dạy cho quy trình Oauth2Login cách đọc role từ Keycloak
//     @Bean
//     public GrantedAuthoritiesMapper userAuthoritiesMapper() {
//         return (authorities) -> {
//             Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

//             //DEBUG
//             System.out.println("--- [DEBUG] BẮT ĐẦU KIỂM TRA QUYỀN ---");
//             System.out.println("CÁC QUYỀN GỐC TỪ KEYCLOAK: " + authorities);
//             // --- 

//             authorities.forEach(authority -> {
//                 if (authority instanceof OidcUserAuthority oidcAuth) {
//                     Map<String, Object> realmAccess = (Map<String, Object>) oidcAuth.getAttributes().get("realm_access");
//                     if (realmAccess != null && realmAccess.containsKey("roles")) {
//                         Collection<String> roles = (Collection<String>) realmAccess.get("roles");

//                          // --- LOGGING ---
//                         System.out.println("ĐÃ TÌM THẤY ROLES TRONG REALM_ACCESS: " + roles);
//                         // --- 

//                         mappedAuthorities.addAll(roles.stream()
//                                 .map(roleName -> new SimpleGrantedAuthority("ROLE_" + roleName.toUpperCase()))
//                                 .collect(Collectors.toSet()));
//                     }
//                 } else if (authority instanceof OAuth2UserAuthority oauth2Auth) {
//                     Map<String, Object> realmAccess = (Map<String, Object>) oauth2Auth.getAttributes().get("realm_access");
//                     if (realmAccess != null && realmAccess.containsKey("roles")) {
//                         Collection<String> roles = (Collection<String>) realmAccess.get("roles");
//                         mappedAuthorities.addAll(roles.stream()
//                                 .map(roleName -> new SimpleGrantedAuthority("ROLE_" + roleName.toUpperCase()))
//                                 .collect(Collectors.toSet()));
//                     }
//                 } else {
//                     mappedAuthorities.add(authority);
//                 }
//             });
            
            
//             // --- LOGGING ---
//             System.out.println("CÁC QUYỀN SAU KHI XỬ LÝ: " + mappedAuthorities);
//             System.out.println("--- [DEBUG] KẾT THÚC KIỂM TRA QUYỀN ---");
//             // --- 

//             return mappedAuthorities;
//         };
//     }

    
//     @Bean
//     public JwtAuthenticationConverter jwtAuthenticationConverter() {
//         JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
//         jwtConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
//             Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");
//             if (realmAccess == null || realmAccess.isEmpty()) {
//                 return Collections.emptyList();
//             }
//             Collection<String> roles = (Collection<String>) realmAccess.get("roles");
//             if (roles == null) {
//                 return Collections.emptyList();
//             }
//             return roles.stream()
//                     .map(roleName -> "ROLE_" + roleName.toUpperCase())
//                     .map(SimpleGrantedAuthority::new)
//                     .collect(Collectors.toList());
//         });
//         return jwtConverter;
//     }
// }

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final ClientRegistrationRepository clientRegistrationRepository;

    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/public/**", "/", "/register", "/vulnerable/**").permitAll()
                // /api/vulnerable/** in realm EXTERNAL
                .requestMatchers("/api/vulnerable/**").authenticated()
                .requestMatchers("/dashboard").authenticated()
                .requestMatchers("/web/user/**").hasRole("USER")
                .requestMatchers("/web/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("/dashboard", true)
                .userInfoEndpoint(userInfo -> userInfo.userAuthoritiesMapper(userAuthoritiesMapper()))
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .authenticationManagerResolver(jwtAuthenticationManagerResolver()) 
            )
            .logout(logout -> logout
                .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository))
            );

        return http.build();
    }

    // === Use JwtAuthenticationConverter ===
    @Bean
    public JwtIssuerAuthenticationManagerResolver jwtAuthenticationManagerResolver() {
        String issuerSpringRealm = "http://localhost:8081/realms/spring-boot-realm";
        String issuerExternal = "http://localhost:8081/realms/realm-external";
        
        // Create map for AuthenticationManager reference to issuer
        Map<String, AuthenticationManager> authenticationManagers = Map.of(
            issuerSpringRealm, createAuthenticationManager(issuerSpringRealm),
            issuerExternal, createAuthenticationManager(issuerExternal)
        );

        return new JwtIssuerAuthenticationManagerResolver(authenticationManagers::get);
    }

    // Hàm phụ trợ để tạo AuthenticationManager với custom converter
    private AuthenticationManager createAuthenticationManager(String issuer) {
        //ban dau 
        // JwtDecoder jwtDecoder = JwtDecoders.fromOidcIssuerLocation(issuer);
        // JwtAuthenticationProvider provider = new JwtAuthenticationProvider(jwtDecoder);
        // // Quan trọng: Gắn converter của bạn vào provider
        // provider.setJwtAuthenticationConverter(jwtAuthenticationConverter());
        // return provider::authenticate;
        try {
        // Build a JwtDecoder using the issuer's metadata (so signature verification uses that issuer's JWKs)
        // This ensures signature verification still occurs with the correct key for each realm.
        JwtDecoder jwtDecoder = JwtDecoders.fromOidcIssuerLocation(issuer);

        // LAB-ONLY: If it's a NimbusJwtDecoder we disable claim validators so iss/aud/exp checks are skipped.
        // This reproduces the "accept token from other tenant" behavior.
        // if (jwtDecoder instanceof NimbusJwtDecoder nimbusDecoder) {
        //     nimbusDecoder.setJwtValidator(jwt -> OAuth2TokenValidatorResult.success());
        // }
        //version2 for vul6
        if (issuer.contains("realm-external") && jwtDecoder instanceof NimbusJwtDecoder nimbusDecoder) {
            nimbusDecoder.setJwtValidator(jwt -> {
                System.out.println("[LAB] Bỏ qua kiểm tra issuer/audience cho realm-external");
                return OAuth2TokenValidatorResult.success();
            });
        }

        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(jwtDecoder);
        provider.setJwtAuthenticationConverter(jwtAuthenticationConverter());
        return provider::authenticate;
        } catch (Exception ex) {
            // In lab, log and return failing auth manager as fallback
            System.out.println("LAB: Failed to create permissive AuthenticationManager for issuer=" + issuer + " error=" + ex.getMessage());
            return authentication -> { throw new BadCredentialsException("Failed to configure decoder for issuer: " + issuer); };
        }
    }
    // ===================================


    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority oidcAuth) {
                    Map<String, Object> realmAccess = (Map<String, Object>) oidcAuth.getAttributes().get("realm_access");
                    if (realmAccess != null && realmAccess.containsKey("roles")) {
                        Collection<String> roles = (Collection<String>) realmAccess.get("roles");
                        mappedAuthorities.addAll(roles.stream()
                            .map(roleName -> new SimpleGrantedAuthority("ROLE_" + roleName.toUpperCase()))
                            .collect(Collectors.toSet()));
                    }
                } else if (authority instanceof OAuth2UserAuthority oauth2Auth) {
                    Map<String, Object> realmAccess = (Map<String, Object>) oauth2Auth.getAttributes().get("realm_access");
                    if (realmAccess != null && realmAccess.containsKey("roles")) {
                        Collection<String> roles = (Collection<String>) realmAccess.get("roles");
                        mappedAuthorities.addAll(roles.stream()
                            .map(roleName -> new SimpleGrantedAuthority("ROLE_" + roleName.toUpperCase()))
                            .collect(Collectors.toSet()));
                    }
                } else {
                    mappedAuthorities.add(authority);
                }
            });
            return mappedAuthorities;
        };
    }

    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
        OidcClientInitiatedLogoutSuccessHandler handler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        handler.setPostLogoutRedirectUri("http://localhost:8080/");
        return handler;
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");
            if (realmAccess == null || realmAccess.isEmpty()) {
                return Collections.emptyList();
            }
            Collection<String> roles = (Collection<String>) realmAccess.get("roles");
            if (roles == null) {
                return Collections.emptyList();
            }
            return roles.stream()
                .map(roleName -> "ROLE_" + roleName.toUpperCase())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        });
        return jwtConverter;
    }
}