package com.demo.controller;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * CẢNH BÁO: Controller này CỐ TÌNH triển khai luồng OAuth2 một cách KHÔNG AN TOÀN.
 * Dùng để tái hiện Lỗ hổng 1, 2, 3 (CSRF, appId poisoning, IdP poisoning).
 */


@Controller
@RequestMapping("/vulnerable")
public class VulnerableAuthController {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    public VulnerableAuthController(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @GetMapping("/start-login")
    public void startManualLogin(HttpServletResponse response,
                                 @RequestParam(value = "reg", defaultValue = "keycloak") String registrationId,
                                 @RequestParam(value = "client_id", required = false) String clientId) throws IOException {
        System.out.println("vulnerable.start-login called for registrationId=" + registrationId + ", clientIdParam=" + clientId);

        ClientRegistration client = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        if (client == null) {
            System.out.println("ERROR: no client registration found for id=" + registrationId);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unknown registrationId");
            return;
        }

        if (clientId == null || clientId.isBlank()) {
            clientId = client.getClientId();
        }

        // VULNERABLE: set cookies writable by JS/attacker in lab
        ResponseCookie appCookie = ResponseCookie.from("currentApp", clientId)
                .path("/")
                .httpOnly(false)   // intentionally vulnerable for lab
                .secure(false)
                .sameSite("Lax")
                .build();
        response.addHeader("Set-Cookie", appCookie.toString());

        ResponseCookie idpCookie = ResponseCookie.from("currentIdP", registrationId)
                .path("/")
                .httpOnly(false)   // intentionally vulnerable for lab
                .secure(false)
                .sameSite("Lax")
                .build();
        response.addHeader("Set-Cookie", idpCookie.toString());

        String authUri = client.getProviderDetails().getAuthorizationUri();
        String redirectUri = "http://localhost:8080/vulnerable/handle-callback";
        String authorizationUrl = authUri +
                "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                "&response_type=code" +
                "&scope=" + URLEncoder.encode(String.join(" ", client.getScopes()), StandardCharsets.UTF_8) +
                "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
                // intentionally NOT adding state to demonstrate vulnerable flow

        System.out.println("AUTH URL: " + authorizationUrl);
        response.sendRedirect(authorizationUrl);
    }

    @GetMapping("/set-current-app")
    public void setCurrentApp(HttpServletResponse response,
                              @RequestParam("app") String appId) throws IOException {
        ResponseCookie appCookie = ResponseCookie.from("currentApp", appId)
                .path("/")
                .httpOnly(false)
                .secure(false)
                .sameSite("Lax")
                .build();
        response.addHeader("Set-Cookie", appCookie.toString());
        response.getWriter().write("ok");
    }

    @GetMapping("/set-current-idp")
    public void setCurrentIdp(HttpServletResponse response,
                              @RequestParam("idp") String idp) throws IOException {
        ResponseCookie idpCookie = ResponseCookie.from("currentIdP", idp)
                .path("/")
                .httpOnly(false)
                .secure(false)
                .sameSite("Lax")
                .build();
        response.addHeader("Set-Cookie", idpCookie.toString());
        response.getWriter().write("ok");
    }


    //access with token for vul6
    @GetMapping("/login-with-token")
    public String loginWithToken(@RequestParam("access_token") String accessToken,
                                HttpServletRequest request) {
        // 1) quick decode (no signature verification) - lab only
        String[] parts = accessToken.split("\\.");
        if (parts.length < 2) return "redirect:/?error=true";
        try {
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            ObjectMapper om = new ObjectMapper();
            Map<String,Object> claims = om.readValue(payload, Map.class);
            String username = (String) claims.getOrDefault("email", claims.get("preferred_username"));
            if (username == null) return "redirect:/?error=true";

            UserDetails userDetails = User.withUsername(username)
                    .password("") // SSO
                    .authorities(new SimpleGrantedAuthority("ROLE_USER"))
                    .build();

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            HttpSession session = request.getSession(true);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

            System.out.println("LAB: created session for user=" + username);
            return "redirect:/dashboard";
        } catch (Exception ex) {
            ex.printStackTrace();
            return "redirect:/?error=true";
        }
    }

    /**
     * Modified vulnerable callback: now sets Set-Cookie on successful login so browser persists currentApp/currentIdP.
     * Keep vulnerable selection order: state -> iss -> cookie. No consistency checks.
     */
    @GetMapping("/handle-callback")
    public String handleManualCallback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "state", required = false) String stateParam,
            @RequestParam(value = "iss", required = false) String iss,
            HttpServletRequest request,
            HttpServletResponse response) {

        System.out.println("vulnerable.handle-callback called with code=" + code + ", state=" + stateParam + ", iss=" + iss);

        // read cookie values received in the request
        String cookieIdP = null;
        String cookieApp = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if ("currentIdP".equals(c.getName())) cookieIdP = c.getValue();
                if ("currentApp".equals(c.getName())) cookieApp = c.getValue();
            }
        }
        System.out.println("Cookie currentIdP = " + cookieIdP + ", currentApp = " + cookieApp);

        if (code == null) {
            System.out.println("No code provided in callback.");
            return "redirect:/?error=true";
        }

        String registrationId = null;

        // 1) parse state (if it encodes registration)
        if (stateParam != null && stateParam.contains(":")) {
            try {
                String decodedState = URLDecoder.decode(stateParam, StandardCharsets.UTF_8);
                String[] parts = decodedState.split(":", 2);
                if (parts.length >= 1) {
                    registrationId = parts[0];
                    System.out.println("Detected registrationId from state: " + registrationId);
                }
            } catch (Exception ex) {
                System.out.println("Failed to decode state: " + ex.getMessage());
            }
        }

        // 2) match by iss if provided (vulnerable: we accept iss param)
        if (registrationId == null && iss != null && !iss.isBlank()) {
            try {
                String decodedIss = URLDecoder.decode(iss, StandardCharsets.UTF_8);
                System.out.println("Decoded iss: " + decodedIss);

                // Candidate registrations defined in your application.yml:
                String[] candidateIds = new String[] { "keycloak", "keycloak-external",  "keycloak-attacker-same-realm"};

                for (String candidate : candidateIds) {
                    ClientRegistration c = this.clientRegistrationRepository.findByRegistrationId(candidate);
                    if (c == null) continue;
                    String providerIssuer = c.getProviderDetails().getIssuerUri();
                    if (providerIssuer != null && providerIssuer.equals(decodedIss)) {
                        registrationId = candidate;
                        System.out.println("Matched registration by issuerUri -> " + candidate);
                        break;
                    }
                    String authUri = c.getProviderDetails().getAuthorizationUri();
                    if (authUri != null && authUri.contains(decodedIss)) {
                        registrationId = candidate;
                        System.out.println("Matched registration by authorizationUri -> " + candidate);
                        break;
                    }
                }
            } catch (Exception ex) {
                // ignore
            }
        }

        // 3) fallback to cookie (vulnerable behaviour)
        if (registrationId == null && cookieIdP != null) {
            registrationId = cookieIdP;
            System.out.println("Falling back to cookie registrationId -> " + registrationId);
        }

        if (registrationId == null) {
            System.out.println("Cannot determine registrationId for code; aborting.");
            return "redirect:/?error=true";
        }

        if (cookieIdP != null && !cookieIdP.equals(registrationId)) {
            System.out.println("!!! MIX-UP CONDITION DETECTED: cookieIdP=" + cookieIdP + " but selected registration=" + registrationId);
            System.out.println("!!! VULNERABLE BEHAVIOR: proceeding to exchange code with registration=" + registrationId + " despite mismatch.");
        }

        ClientRegistration client = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        if (client == null) {
            System.out.println("Client registration not found for id=" + registrationId);
            return "redirect:/?error=true";
        }

        // Redeem code using chosen client (vulnerable exchange)
        String tokenUri = client.getProviderDetails().getTokenUri();
        String clientId = client.getClientId();
        String clientSecret = client.getClientSecret();
        String redirectUri = "http://localhost:8080/vulnerable/handle-callback";

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "authorization_code");
        map.add("client_id", clientId);
        if (clientSecret != null && !clientSecret.isBlank()) {
            map.add("client_secret", clientSecret);
        }
        map.add("code", code);
        map.add("redirect_uri", redirectUri);

        HttpEntity<MultiValueMap<String, String>> httpRequest = new HttpEntity<>(map, headers);

        try {
            ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(tokenUri, httpRequest, Map.class);
            Map<String, Object> responseBody = tokenResponse.getBody();

            if (responseBody == null || !responseBody.containsKey("access_token")) {
                System.out.println("Token exchange failed or returned no access_token. Status: " + tokenResponse.getStatusCode());
                System.out.println("Response body: " + responseBody);
                return "redirect:/?error=true";
            }

            String accessToken = (String) responseBody.get("access_token");
            System.out.println("Token exchange OK for registration=" + registrationId + " (access_token len=" + (accessToken == null ? 0 : accessToken.length()) + ")");

            // --- Persist cookies for demo: set currentApp/currentIdP in response so browser stores them ---
            // Prefer cookieApp (attacker-provided) if present, otherwise use registrationId/clientId
            String toPersistApp = (cookieApp != null && !cookieApp.isBlank()) ? cookieApp : clientId;
            ResponseCookie persistentApp = ResponseCookie.from("currentApp", toPersistApp)
                    .path("/")
                    .httpOnly(false)  // lab-only: allow JS visibility
                    .secure(false)
                    .sameSite("Lax")
                    .build();
            response.addHeader("Set-Cookie", persistentApp.toString());

            // Also persist currentIdP to the resolved registrationId (so future fallback uses it)
            ResponseCookie persistentIdp = ResponseCookie.from("currentIdP", registrationId)
                    .path("/")
                    .httpOnly(false)
                    .secure(false)
                    .sameSite("Lax")
                    .build();
            response.addHeader("Set-Cookie", persistentIdp.toString());

            // --- Lab login stub version 1 ---
            // UserDetails userDetails = User.withUsername("vulnerable_user")
            //         .password("")
            //         .authorities(new SimpleGrantedAuthority("ROLE_USER"))
            //         .build();

            // UsernamePasswordAuthenticationToken authentication =
            //         new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            // SecurityContext context = SecurityContextHolder.createEmptyContext();
            // context.setAuthentication(authentication);
            // SecurityContextHolder.setContext(context);

            // HttpSession session = request.getSession(true);
            // session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

            // System.out.println("!!! CẢNH BÁO: Đăng nhập thành công qua callback không an toàn (registration=" + registrationId + ") !!!");
            // return "redirect:/dashboard";

            //Login stub version 2
            // String idToken = (String) responseBody.get("id_token");
            // String email = null;

            // // Quick decode id_token payload (lab debug)
            // if (idToken != null) {
            //     try {
            //         String[] parts = idToken.split("\\.");
            //         if (parts.length >= 2) {
            //             String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            //             com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
            //             java.util.Map<String,Object> claims = om.readValue(payload, java.util.Map.class);
            //             email = (String) claims.get("email");
            //             System.out.println("LAB DEBUG: id_token claims email=" + email + ", iss=" + claims.get("iss") + ", sub=" + claims.get("sub"));
            //         }
            //     } catch (Exception ex) {
            //         System.out.println("LAB DEBUG: failed to decode id_token: " + ex.getMessage());
            //     }
            // }

            // // Fallback: call UserInfo if needed
            // if (email == null) {
            //     try {
            //         String userInfoUri = client.getProviderDetails().getUserInfoEndpoint().getUri();
            //         if (userInfoUri != null) {
            //             HttpHeaders uiHeaders = new HttpHeaders();
            //             uiHeaders.setBearerAuth((String) responseBody.get("access_token"));
            //             HttpEntity<Void> uiReq = new HttpEntity<>(uiHeaders);
            //             RestTemplate rt = new RestTemplate();
            //             ResponseEntity<Map> uiResp = rt.exchange(userInfoUri, HttpMethod.GET, uiReq, Map.class);
            //             Map<String,Object> uiBody = uiResp.getBody();
            //             if (uiBody != null) {
            //                 email = (String) uiBody.get("email");
            //                 System.out.println("LAB DEBUG: userinfo email=" + email);
            //             }
            //         }
            //     } catch (Exception ex) {
            //         System.out.println("LAB DEBUG: userinfo call failed: " + ex.getMessage());
            //     }
            // }

            // if (email != null && !email.isBlank()) {
            //     System.out.println("LAB VULN: Auto-mapping by email -> logging in as " + email);
            //     UserDetails userDetails = User.withUsername(email)
            //         .password("") // SSO login
            //         .authorities(new SimpleGrantedAuthority("ROLE_USER"))
            //         .build();

            //     UsernamePasswordAuthenticationToken authentication =
            //         new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            //     SecurityContext context = SecurityContextHolder.createEmptyContext();
            //     context.setAuthentication(authentication);
            //     SecurityContextHolder.setContext(context);

            //     HttpSession session = request.getSession(true);
            //     session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

            //     return "redirect:/dashboard";
            // }

            //login stub version3
            // String idToken = (String) responseBody.get("id_token");
            // String email = null;
            // String fallbackUsername = null;

            // // Ghi log toàn bộ response body để debug
            // try {
            //     System.out.println("LAB DEBUG: token response body: " + new ObjectMapper().writeValueAsString(responseBody));
            // } catch (Exception ignore) {}

            // // 1) Thử lấy thông tin từ id_token
            // if (idToken != null) {
            //     try {
            //         String[] parts = idToken.split("\\.");
            //         if (parts.length >= 2) {
            //             String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            //             ObjectMapper om = new ObjectMapper();
            //             Map<String, Object> claims = om.readValue(payload, Map.class);
            //             email = (String) claims.get("email");
            //             fallbackUsername = (String) claims.get("preferred_username");
            //             if (fallbackUsername == null) fallbackUsername = (String) claims.get("sub");
            //             System.out.println("LAB DEBUG: id_token claims email=" + email + ", preferred_username=" + claims.get("preferred_username") + ", sub=" + claims.get("sub"));
            //         }
            //     } catch (Exception ex) {
            //         System.out.println("LAB DEBUG: failed to decode id_token: " + ex.getMessage());
            //     }
            // }

            // // 2) Nếu không có email, thử giải mã access_token
            // if ((email == null || email.isBlank()) && accessToken != null) {
            //     try {
            //         String[] parts = accessToken.split("\\.");
            //         if (parts.length >= 2) {
            //             String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            //             ObjectMapper om = new ObjectMapper();
            //             Map<String, Object> claims = om.readValue(payload, Map.class);
            //             if (claims.get("email") != null) email = (String) claims.get("email");
            //             if (fallbackUsername == null && claims.get("preferred_username") != null) fallbackUsername = (String) claims.get("preferred_username");
            //             if (fallbackUsername == null && claims.get("sub") != null) fallbackUsername = (String) claims.get("sub");
            //             System.out.println("LAB DEBUG: access_token claims email=" + email + ", sub=" + claims.get("sub"));
            //         }
            //     } catch (Exception ex) {
            //         System.out.println("LAB DEBUG: failed to decode access_token: " + ex.getMessage());
            //     }
            // }

            // // 3) Nếu vẫn không có, gọi UserInfo endpoint
            // if ((email == null || email.isBlank()) && client.getProviderDetails().getUserInfoEndpoint() != null) {
            //     try {
            //         String userInfoUri = client.getProviderDetails().getUserInfoEndpoint().getUri();
            //         if (userInfoUri != null) {
            //             HttpHeaders uiHeaders = new HttpHeaders();
            //             uiHeaders.setBearerAuth(accessToken);
            //             HttpEntity<Void> uiReq = new HttpEntity<>(uiHeaders);
            //             RestTemplate rt = new RestTemplate();
            //             ResponseEntity<Map> uiResp = rt.exchange(userInfoUri, HttpMethod.GET, uiReq, Map.class);
            //             Map<String, Object> uiBody = uiResp.getBody();
            //             if (uiBody != null) {
            //                 System.out.println("LAB DEBUG: userinfo response: " + uiBody);
            //                 if (uiBody.get("email") != null) email = (String) uiBody.get("email");
            //                 if (fallbackUsername == null && uiBody.get("preferred_username") != null) fallbackUsername = (String) uiBody.get("preferred_username");
            //                 if (fallbackUsername == null && uiBody.get("sub") != null) fallbackUsername = (String) uiBody.get("sub");
            //             }
            //         }
            //     } catch (Exception ex) {
            //         System.out.println("LAB DEBUG: userinfo call failed: " + ex.getMessage());
            //     }
            // }

            // // 4) Quyết định username cuối cùng để đăng nhập
            // String usernameToUse = null;
            // if (email != null && !email.isBlank()) {
            //     usernameToUse = email;
            // } else if (fallbackUsername != null && !fallbackUsername.isBlank()) {
            //     usernameToUse = fallbackUsername;
            // }

            // if (usernameToUse != null) {
            //     System.out.println("LAB VULN: Auto-mapping by identity -> logging in as " + usernameToUse);
            //     UserDetails userDetails = User.withUsername(usernameToUse)
            //             .password("") // SSO login
            //             .authorities(new SimpleGrantedAuthority("ROLE_USER"))
            //             .build();

            //     UsernamePasswordAuthenticationToken authentication =
            //             new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            //     SecurityContext context = SecurityContextHolder.createEmptyContext();
            //     context.setAuthentication(authentication);
            //     SecurityContextHolder.setContext(context);

            //     HttpSession session = request.getSession(true);
            //     session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

            //     return "redirect:/dashboard";
            // } else {
            //     System.out.println("LAB DEBUG: no identity found in id_token/access_token/userinfo -> aborting login");
            // }

            //login stub version 4 - strict email
            String idToken = (String) responseBody.get("id_token");
            String email = null;
            String fallbackUsername = null;

            // Try extract email from id_token (lab-only, no issuer check)
            if (idToken != null) {
                try {
                    String[] parts = idToken.split("\\.");
                    if (parts.length >= 2) {
                        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                        ObjectMapper om = new ObjectMapper();
                        Map<String, Object> claims = om.readValue(payload, Map.class);
                        email = (String) claims.get("email");
                        fallbackUsername = (String) claims.get("preferred_username");
                        if (fallbackUsername == null) fallbackUsername = (String) claims.get("sub");
                        System.out.println("LAB DEBUG: id_token claims email=" + email + ", iss=" + claims.get("iss"));
                    }
                } catch (Exception ex) {
                    System.out.println("LAB DEBUG: failed to decode id_token: " + ex.getMessage());
                }
            }

            if (email != null && !email.isBlank()) {
                System.out.println("LAB VULN: Auto-mapping by identity -> logging in as " + email);
                UserDetails userDetails = User.withUsername(email)
                        .password("") // SSO login
                        .authorities(new SimpleGrantedAuthority("ROLE_USER"))
                        .build();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);

                HttpSession session = request.getSession(true);
                session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

                return "redirect:/dashboard";
            }
            
        } catch (org.springframework.web.client.HttpClientErrorException he) {
            System.out.println("Token endpoint error: " + he.getStatusCode() + " body=" + he.getResponseBodyAsString());
            he.printStackTrace();
            return "redirect:/?error=true";
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/?error=true";
        }
        return "redirect:/?error=true"; //them 
    }


    /**
     * LAB-ONLY: Auto-redirect endpoint to simulate Login CSRF / forced authorize.
     * Example: GET /vulnerable/auto-redirect?client_id=attacker-client&redirect_uri=http://attacker.local/receive
     *
     * If user already has SSO session and client does not require consent, this causes an immediate redirect
     * to the IdP authorize endpoint and then to redirect_uri with code (no user interaction).
     */
    // @GetMapping("/auto-redirect")
    // public void autoRedirect(HttpServletResponse response,
    //                         @RequestParam("client_id") String clientId,
    //                         @RequestParam("redirect_uri") String redirectUri) throws IOException {
    //     // LAB-only: build authorization URL for the main realm (or attacker realm as you like)
    //     String authUrl = "http://localhost:8081/realms/spring-boot-realm/protocol/openid-connect/auth" +
    //             "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
    //             "&response_type=code" +
    //             "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8) +
    //             "&scope=openid%20profile%20email";
    //     System.out.println("LAB auto-redirect -> " + authUrl);
    //     response.sendRedirect(authUrl);
    // }
    @GetMapping("/auto-redirect")
    public void autoRedirect(HttpServletResponse response,
                         @RequestParam(value="reg", required=false) String registrationId,
                         @RequestParam("client_id") String clientId,
                         @RequestParam("redirect_uri") String redirectUri) throws IOException {

        ClientRegistration client = null;
        if (registrationId != null) {
            client = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        } else {
            // fallback: find by clientId
            Iterable<ClientRegistration> regs = ((Iterable<ClientRegistration>) this.clientRegistrationRepository);
            for (ClientRegistration r : regs) {
                if (r.getClientId().equals(clientId)) { client = r; break; }
            }
        }

        String authBase;
        if (client != null) {
            authBase = client.getProviderDetails().getAuthorizationUri();
        } else {
            // fallback to default realm if not found
            authBase = "http://localhost:8081/realms/spring-boot-realm/protocol/openid-connect/auth";
        }

        String authUrl = authBase +
                "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
                "&response_type=code" +
                "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8) +
                "&scope=openid%20profile%20email";

        System.out.println("LAB auto-redirect -> " + authUrl);
        response.sendRedirect(authUrl);
    }
}


// @Controller
// @RequestMapping("/vulnerable")
// public class VulnerableAuthController {

//     private final ClientRegistrationRepository clientRegistrationRepository;

//     @Autowired
//     public VulnerableAuthController(ClientRegistrationRepository clientRegistrationRepository) {
//         this.clientRegistrationRepository = clientRegistrationRepository;
//     }

//     /**
//      * Start vulnerable login:
//      * - lưu currentApp và currentIdP vào cookie (NOT HttpOnly) để mô phỏng poisoning
//      * - redirect đến authorization endpoint của IdP, redirect_uri trỏ về /vulnerable/handle-callback
//      *
//      * Usage examples:
//      *  - /vulnerable/start-login?reg=keycloak&client_id=spring-boot-client
//      *  - /vulnerable/start-login?reg=keycloak-external&client_id=external-client
//      */
//     @GetMapping("/start-login")
//     public void startManualLogin(HttpServletResponse response,
//                                  @RequestParam(value = "reg", defaultValue = "keycloak") String registrationId,
//                                  @RequestParam(value = "client_id", required = false) String clientId) throws IOException {
//         System.out.println("vulnerable.start-login called for registrationId=" + registrationId + ", clientIdParam=" + clientId);

//         ClientRegistration client = this.clientRegistrationRepository.findByRegistrationId(registrationId);
//         if (client == null) {
//             System.out.println("ERROR: no client registration found for id=" + registrationId);
//             response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unknown registrationId");
//             return;
//         }

//         if (clientId == null || clientId.isBlank()) {
//             clientId = client.getClientId();
//         }

//         // VULNERABLE: set cookies writable by JS/attacker in lab
//         ResponseCookie appCookie = ResponseCookie.from("currentApp", clientId)
//                 .path("/")
//                 .httpOnly(false)   // intentionally vulnerable for lab
//                 .secure(false)
//                 .sameSite("Lax")
//                 .build();
//         response.addHeader("Set-Cookie", appCookie.toString());

//         ResponseCookie idpCookie = ResponseCookie.from("currentIdP", registrationId)
//                 .path("/")
//                 .httpOnly(false)   // intentionally vulnerable for lab
//                 .secure(false)
//                 .sameSite("Lax")
//                 .build();
//         response.addHeader("Set-Cookie", idpCookie.toString());

//         // Build authorization URL, redirect_uri points to our vulnerable callback
//         String authUri = client.getProviderDetails().getAuthorizationUri();
//         String redirectUri = "http://localhost:8080/vulnerable/handle-callback";
//         String authorizationUrl = authUri +
//                 "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
//                 "&response_type=code" +
//                 "&scope=" + URLEncoder.encode(String.join(" ", client.getScopes()), StandardCharsets.UTF_8) +
//                 "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
//                 // intentionally NOT adding state to demonstrate vulnerable flow

//         System.out.println("AUTH URL: " + authorizationUrl);
//         response.sendRedirect(authorizationUrl);
//     }

//     /**
//      * Lab-only helpers for attacker to overwrite cookies on victim browser.
//      * In real attack you'd use iframe/JS or social-engineer victim to hit these endpoints.
//      */
//     @GetMapping("/set-current-app")
//     public void setCurrentApp(HttpServletResponse response,
//                               @RequestParam("app") String appId) throws IOException {
//         ResponseCookie appCookie = ResponseCookie.from("currentApp", appId)
//                 .path("/")
//                 .httpOnly(false)
//                 .secure(false)
//                 .sameSite("Lax")
//                 .build();
//         response.addHeader("Set-Cookie", appCookie.toString());
//         response.getWriter().write("ok");
//     }

//     @GetMapping("/set-current-idp")
//     public void setCurrentIdp(HttpServletResponse response,
//                               @RequestParam("idp") String idp) throws IOException {
//         ResponseCookie idpCookie = ResponseCookie.from("currentIdP", idp)
//                 .path("/")
//                 .httpOnly(false)
//                 .secure(false)
//                 .sameSite("Lax")
//                 .build();
//         response.addHeader("Set-Cookie", idpCookie.toString());
//         response.getWriter().write("ok");
//     }

//     /**
//      * Vulnerable callback implementing mix-up / appId poisoning behavior:
//      *   Determine registrationId in order: state -> iss -> cookie
//      *   Do NOT verify consistency between cookie/currentIdP and chosen registration
//      *   Proceed to token exchange with chosen registration (vulnerable)
//      */
//     @GetMapping("/handle-callback")
//     public String handleManualCallback(
//             @RequestParam(value = "code", required = false) String code,
//             @RequestParam(value = "state", required = false) String stateParam,
//             @RequestParam(value = "iss", required = false) String iss,
//             HttpServletRequest request) {

//         System.out.println("vulnerable.handle-callback called with code=" + code + ", state=" + stateParam + ", iss=" + iss);

//         // read cookie values
//         String cookieIdP = null;
//         String cookieApp = null;
//         Cookie[] cookies = request.getCookies();
//         if (cookies != null) {
//             for (Cookie c : cookies) {
//                 if ("currentIdP".equals(c.getName())) cookieIdP = c.getValue();
//                 if ("currentApp".equals(c.getName())) cookieApp = c.getValue();
//             }
//         }
//         System.out.println("Cookie currentIdP = " + cookieIdP + ", currentApp = " + cookieApp);

//         if (code == null) {
//             System.out.println("No code provided in callback.");
//             return "redirect:/?error=true";
//         }

//         String registrationId = null;

//         // 1) parse state (if it encodes registration)
//         if (stateParam != null && stateParam.contains(":")) {
//             try {
//                 String decodedState = URLDecoder.decode(stateParam, StandardCharsets.UTF_8);
//                 String[] parts = decodedState.split(":", 2);
//                 if (parts.length >= 1) {
//                     registrationId = parts[0];
//                     System.out.println("Detected registrationId from state: " + registrationId);
//                 }
//             } catch (Exception ex) {
//                 System.out.println("Failed to decode state: " + ex.getMessage());
//             }
//         }

//         // 2) match by iss if provided (vulnerable: we accept iss param)
//         if (registrationId == null && iss != null && !iss.isBlank()) {
//             try {
//                 String decodedIss = URLDecoder.decode(iss, StandardCharsets.UTF_8);
//                 System.out.println("Decoded iss: " + decodedIss);

//                 // Candidate registrations defined in your application.yml:
//                 // (we use the exact registration IDs present in application.yml)
//                 String[] candidateIds = new String[] { "keycloak", "keycloak-external" };

//                 for (String candidate : candidateIds) {
//                     ClientRegistration c = this.clientRegistrationRepository.findByRegistrationId(candidate);
//                     if (c == null) continue;
//                     String providerIssuer = c.getProviderDetails().getIssuerUri();
//                     if (providerIssuer != null && providerIssuer.equals(decodedIss)) {
//                         registrationId = candidate;
//                         System.out.println("Matched registration by issuerUri -> " + candidate);
//                         break;
//                     }
//                     String authUri = c.getProviderDetails().getAuthorizationUri();
//                     if (authUri != null && authUri.contains(decodedIss)) {
//                         registrationId = candidate;
//                         System.out.println("Matched registration by authorizationUri -> " + candidate);
//                         break;
//                     }
//                 }
//             } catch (Exception ex) {
//                 // ignore
//             }
//         }

//         // 3) fallback to cookie (vulnerable behaviour)
//         if (registrationId == null && cookieIdP != null) {
//             registrationId = cookieIdP;
//             System.out.println("Falling back to cookie registrationId -> " + registrationId);
//         }

//         if (registrationId == null) {
//             System.out.println("Cannot determine registrationId for code; aborting.");
//             return "redirect:/?error=true";
//         }

//         // log mix-up if cookie says different IdP than chosen registration
//         if (cookieIdP != null && !cookieIdP.equals(registrationId)) {
//             System.out.println("!!! MIX-UP CONDITION DETECTED: cookieIdP=" + cookieIdP + " but selected registration=" + registrationId);
//             System.out.println("!!! VULNERABLE BEHAVIOR: proceeding to exchange code with registration=" + registrationId + " despite mismatch.");
//         }

//         ClientRegistration client = this.clientRegistrationRepository.findByRegistrationId(registrationId);
//         if (client == null) {
//             System.out.println("Client registration not found for id=" + registrationId);
//             return "redirect:/?error=true";
//         }

//         // Redeem code using chosen client (vulnerable exchange)
//         String tokenUri = client.getProviderDetails().getTokenUri();
//         String clientId = client.getClientId();
//         String clientSecret = client.getClientSecret();
//         String redirectUri = "http://localhost:8080/vulnerable/handle-callback";

//         RestTemplate restTemplate = new RestTemplate();
//         HttpHeaders headers = new HttpHeaders();
//         headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

//         MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
//         map.add("grant_type", "authorization_code");
//         map.add("client_id", clientId);
//         if (clientSecret != null && !clientSecret.isBlank()) {
//             map.add("client_secret", clientSecret);
//         }
//         map.add("code", code);
//         map.add("redirect_uri", redirectUri);

//         HttpEntity<MultiValueMap<String, String>> httpRequest = new HttpEntity<>(map, headers);

//         try {
//             ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, httpRequest, Map.class);
//             Map<String, Object> responseBody = response.getBody();

//             if (responseBody == null || !responseBody.containsKey("access_token")) {
//                 System.out.println("Token exchange failed or returned no access_token. Status: " + response.getStatusCode());
//                 System.out.println("Response body: " + responseBody);
//                 return "redirect:/?error=true";
//             }

//             String accessToken = (String) responseBody.get("access_token");
//             System.out.println("Token exchange OK for registration=" + registrationId + " (access_token len=" + (accessToken == null ? 0 : accessToken.length()) + ")");

//             // --- Lab login stub ---
//             UserDetails userDetails = User.withUsername("vulnerable_user")
//                     .password("")
//                     .authorities(new SimpleGrantedAuthority("ROLE_USER"))
//                     .build();

//             UsernamePasswordAuthenticationToken authentication =
//                     new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

//             SecurityContext context = SecurityContextHolder.createEmptyContext();
//             context.setAuthentication(authentication);
//             SecurityContextHolder.setContext(context);

//             HttpSession session = request.getSession(true);
//             session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

//             System.out.println("!!! CẢNH BÁO: Đăng nhập thành công qua callback không an toàn (registration=" + registrationId + ") !!!");
//             return "redirect:/dashboard";
//         } catch (org.springframework.web.client.HttpClientErrorException he) {
//             System.out.println("Token endpoint error: " + he.getStatusCode() + " body=" + he.getResponseBodyAsString());
//             he.printStackTrace();
//             return "redirect:/?error=true";
//         } catch (Exception e) {
//             e.printStackTrace();
//             return "redirect:/?error=true";
//         }
//     }
// }




 //Đang chạy ngon
// @Controller
// @RequestMapping("/vulnerable")
// public class VulnerableAuthController {

//     private final ClientRegistrationRepository clientRegistrationRepository;
//     // them hardcoded pkce verifier de tai hien lo hong
//     //private static final String HARDCODED_PKCE_VERIFIER = "a_very_insecure_hardcoded_verifier_for_the_lab";


//     @Autowired
//     public VulnerableAuthController(ClientRegistrationRepository clientRegistrationRepository) {
//         this.clientRegistrationRepository = clientRegistrationRepository;
//     }

//     @GetMapping("/start-login")
//     public void startManualLogin(HttpServletResponse response,  @RequestParam(value = "reg", defaultValue = "keycloak") String registrationId) throws IOException {
//         //Them param reg
//         System.out.println("vulnerable.start-login called for registrationId=" + registrationId); // them params de test code tra ve theo client trong realm
//         // Lấy thông tin client "keycloak" một cách an toàn từ Repository
//         ClientRegistration client = this.clientRegistrationRepository.findByRegistrationId(registrationId); //ban dau la "key cloak"

//         //them
//         if (client == null) {
//             System.out.println("ERROR: no client registration found for id=" + registrationId);
//             response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unknown registrationId");
//             return;
//         }

//         String authUri = client.getProviderDetails().getAuthorizationUri();
//         String clientId = client.getClientId();
        
//         // Trỏ đến callback không an toàn
//         String redirectUri = "http://localhost:8080/vulnerable/handle-callback"; 
//         // === THAY ĐỔI 2: Thêm logic cho PKCE 'plain' ===
//         // Vì phương thức là 'plain' nên code_challenge chính là code_verifier
//         //String codeChallenge = HARDCODED_PKCE_VERIFIER;

//         String authorizationUrl = authUri +
//                 "?client_id=" + clientId +
//                 "&response_type=code" +
//                 //"&scope=" + String.join(" ", client.getScopes()) +
//                 "&scope=" + URLEncoder.encode(String.join(" ", client.getScopes()), StandardCharsets.UTF_8) +
//                 //"&redirect_uri=" + redirectUri;
//                 "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
//                 // Thêm 2 tham số PKCE vào URL
//                 //"&code_challenge=" + codeChallenge +
//                 //"&code_challenge_method=plain";

//         // Chuyển hướng người dùng đến Keycloak mà không có 'state'
//         System.out.println("AUTH URL: " + authorizationUrl);
//         response.sendRedirect(authorizationUrl);
//     }



//     //Them request de goi den realm external
//     @GetMapping("/start-login-external")
//     public void startManualLoginExternal(HttpServletResponse response) throws IOException {
//         startManualLogin(response, "keycloak-external");
//     }
    

//     @GetMapping("/handle-callback")
//     public String handleManualCallback(
//             @RequestParam("code") String code,
//             @RequestParam(value = "state", required = false) String stateParam,
//             @RequestParam(value = "iss", required = false) String iss,
//             HttpServletRequest request) {  // THÊM: để truy cập session

//         System.out.println("vulnerable.handle-callback called with code=" + code + ", state=" + stateParam + ", iss=" + iss);

//         String registrationId = null;

//         // 1) Try parse registrationId from state (state format: registrationId:nonce)
//         if (stateParam != null && stateParam.contains(":")) {
//             try {
//                 String decodedState = URLDecoder.decode(stateParam, StandardCharsets.UTF_8);
//                 String[] parts = decodedState.split(":", 2);
//                 if (parts.length >= 1) {
//                     registrationId = parts[0];
//                     System.out.println("Detected registrationId from state: " + registrationId);
//                 }
//             } catch (Exception ex) {
//                 System.out.println("Failed to decode state: " + ex.getMessage());
//             }
//         }

//         // 2) If no registrationId from state, try match using iss (if provided)
//         if (registrationId == null && iss != null && !iss.isBlank()) {
//             try {
//                 String decodedIss = URLDecoder.decode(iss, StandardCharsets.UTF_8);
//                 System.out.println("Decoded iss: " + decodedIss);

//                 String[] candidateIds = new String[] { "keycloak", "keycloak-external" };
//                 for (String candidate : candidateIds) {
//                     ClientRegistration c = this.clientRegistrationRepository.findByRegistrationId(candidate);
//                     if (c == null) continue;
//                     String providerIssuer = c.getProviderDetails().getIssuerUri();
//                     if (providerIssuer != null && providerIssuer.equals(decodedIss)) {
//                         registrationId = candidate;
//                         System.out.println("Matched registration by issuerUri -> " + candidate);
//                         break;
//                     }
//                     String authUri = c.getProviderDetails().getAuthorizationUri();
//                     if (authUri != null && authUri.contains(decodedIss)) {
//                         registrationId = candidate;
//                         System.out.println("Matched registration by authorizationUri -> " + candidate);
//                         break;
//                     }
//                 }
//             } catch (Exception ex) {
//                 // ignore decode error
//             }
//         }

//         if (registrationId == null) {
//             System.out.println("Cannot determine registrationId for code; aborting.");
//             return "redirect:/?error=true";
//         }

//         ClientRegistration client = this.clientRegistrationRepository.findByRegistrationId(registrationId);
//         if (client == null) {
//             System.out.println("Client registration not found for id=" + registrationId);
//             return "redirect:/?error=true";
//         }

//         // Redeem code using the selected client
//         String tokenUri = client.getProviderDetails().getTokenUri();
//         String clientId = client.getClientId();
//         String clientSecret = client.getClientSecret();
//         String redirectUri = "http://localhost:8080/vulnerable/handle-callback";

//         RestTemplate restTemplate = new RestTemplate();
//         HttpHeaders headers = new HttpHeaders();
//         headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

//         MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
//         map.add("grant_type", "authorization_code");
//         map.add("client_id", clientId);
//         if (clientSecret != null && !clientSecret.isBlank()) {
//             map.add("client_secret", clientSecret);
//         }
//         map.add("code", code);
//         map.add("redirect_uri", redirectUri);

//         HttpEntity<MultiValueMap<String, String>> httpRequest = new HttpEntity<>(map, headers);

//         try {
//             ResponseEntity<Map> response = restTemplate.postForEntity(tokenUri, httpRequest, Map.class);
//             Map<String, Object> responseBody = response.getBody();

//             if (responseBody == null || !responseBody.containsKey("access_token")) {
//                 System.out.println("Token exchange failed or returned no access_token. Status: " + response.getStatusCode());
//                 System.out.println("Response body: " + responseBody);
//                 return "redirect:/?error=true";
//             }

//             String accessToken = (String) responseBody.get("access_token");
//             System.out.println("Token exchange OK for registration=" + registrationId + " (access_token len=" + (accessToken == null ? 0 : accessToken.length()) + ")");

//             // --- Log the user in (lab-only stub) ---
//             UserDetails userDetails = User.withUsername("vulnerable_user")
//                     .password("")
//                     .authorities("ROLE_USER")
//                     .build();

//             UsernamePasswordAuthenticationToken authentication =
//                     new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

//             // ✅ SỬA: tạo SecurityContext mới
//             SecurityContext context = SecurityContextHolder.createEmptyContext();
//             context.setAuthentication(authentication);
//             SecurityContextHolder.setContext(context);

//             // ✅ THÊM: lưu SecurityContext vào session để duy trì đăng nhập
//             HttpSession session = request.getSession(true);
//             session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);

//             System.out.println("!!! CẢNH BÁO: Đăng nhập thành công qua callback không an toàn (registration=" + registrationId + ") !!!");
//             return "redirect:/dashboard";
//         } catch (org.springframework.web.client.HttpClientErrorException he) {
//             System.out.println("Token endpoint error: " + he.getStatusCode() + " body=" + he.getResponseBodyAsString());
//             he.printStackTrace();
//             return "redirect:/?error=true";
//         } catch (Exception e) {
//             e.printStackTrace();
//             return "redirect:/?error=true";
//         }
//     }


