package com.demo.service;

import com.demo.entity.User;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import jakarta.ws.rs.core.Response;
import java.util.Collections;

// @Service
// public class KeycloakAdminService {

//     @Value("${keycloak.admin-client.server-url}")
//     private String serverUrl;

//     @Value("${keycloak.admin-client.realm}")
//     private String realm;

//     @Value("${keycloak.admin-client.client-id}")
//     private String clientId;

//     @Value("${keycloak.admin-client.client-secret}")
//     private String clientSecret;

//     public String createUser(User userRequest) { // THAY ĐỔI: Nhận vào User entity
//         Keycloak keycloak = KeycloakBuilder.builder()
//                 .serverUrl(serverUrl)
//                 .realm(realm)
//                 .grantType("client_credentials")
//                 .clientId(clientId)
//                 .clientSecret(clientSecret)
//                 .build();

//         UserRepresentation keycloakUser = new UserRepresentation();
//         keycloakUser.setEnabled(true);
//         keycloakUser.setUsername(userRequest.getUsername());
//         keycloakUser.setEmail(userRequest.getEmail());

//         CredentialRepresentation credential = new CredentialRepresentation();
//         credential.setTemporary(false);
//         credential.setType(CredentialRepresentation.PASSWORD);
//         credential.setValue(userRequest.getPassword()); // Lấy password từ User entity
//         keycloakUser.setCredentials(Collections.singletonList(credential));

//         Response response = keycloak.realm(realm).users().create(keycloakUser);
//         if (response.getStatus() != 201) {
//             String errorMessage = response.readEntity(String.class);
//             throw new RuntimeException("Failed to create user in Keycloak: " + errorMessage);
//         }

//         String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");

//         RoleRepresentation userRole = keycloak.realm(realm).roles().get(userRequest.getRole()).toRepresentation();
//         keycloak.realm(realm).users().get(userId).roles().realmLevel().add(Collections.singletonList(userRole));

//         return userId;
//     }
// }



@Service
public class KeycloakAdminService {

    @Value("${keycloak.admin-client.server-url}")
    private String serverUrl;

    @Value("${keycloak.admin-client.realm}")
    private String realm;

    @Value("${keycloak.admin-client.client-id}")
    private String clientId;

    @Value("${keycloak.admin-client.client-secret}")
    private String clientSecret;

    private Keycloak getKeycloakInstance() {
        return KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .grantType("client_credentials")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
    }

    /**
     * Chỉ tạo user trên Keycloak, chưa gán role.
     * Trả về keycloakId của user vừa tạo.
     */
    public String createUser(User userRequest) {
        Keycloak keycloak = getKeycloakInstance();
        UserRepresentation keycloakUser = new UserRepresentation();
        keycloakUser.setEnabled(true);
        keycloakUser.setUsername(userRequest.getUsername());
        keycloakUser.setEmail(userRequest.getEmail());

        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setTemporary(false);
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(userRequest.getPassword());
        keycloakUser.setCredentials(Collections.singletonList(credential));

        Response response = keycloak.realm(realm).users().create(keycloakUser);
        if (response.getStatus() != 201) {
            String errorMessage = response.readEntity(String.class);
            throw new RuntimeException("Failed to create user in Keycloak: " + errorMessage);
        }

        // Trích xuất ID người dùng từ header 'Location' của response
        return response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
    }

    /**
     * Gán một vai trò cho người dùng dựa trên keycloakId.
     * @param keycloakId ID của người dùng trên Keycloak.
     * @param roleName Tên vai trò cần gán (ví dụ: "USER", "user").
     */
    public void assignRoleToUser(String keycloakId, String roleName) {
        Keycloak keycloak = getKeycloakInstance();
        RealmResource realmResource = keycloak.realm(realm);
        UserResource userResource = realmResource.users().get(keycloakId);

        // SỬA LỖI: Bỏ .toLowerCase() để tìm đúng tên role
        // RoleRepresentation roleToAssign = realmResource.roles().get(roleName).toRepresentation();
        RoleRepresentation roleToAssign = realmResource.roles().get(roleName.toUpperCase()).toRepresentation();

        userResource.roles().realmLevel().add(Collections.singletonList(roleToAssign));
    }
}