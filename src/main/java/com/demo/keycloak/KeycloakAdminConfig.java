package com.demo.keycloak;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakAdminConfig {

    @Value("${keycloak.admin-client.server-url}")
    private String serverUrl;

    @Value("${keycloak.admin-client.realm}")
    private String realm;

    @Value("${keycloak.admin-client.client-id}")
    private String clientId;

    @Value("${keycloak.admin-client.client-secret}")
    private String clientSecret;

    @Bean
    public Keycloak keycloakAdmin() {
        return KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .resteasyClient(
                        ResteasyClientBuilder.newBuilder()
                                .build()
                )
                .build();
    }
}
