package com.demo.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.*;
import lombok.*;

// @Entity
// @Table(name = "users")
// @Data
// @Setter
// @Getter
// @NoArgsConstructor
// @AllArgsConstructor
// public class User {
//    @Id
//     @GeneratedValue(strategy = GenerationType.IDENTITY)
//     private Long id;

//     @Column(unique = true) // Add unique constraint for keycloakId
//     private String keycloakId;

//     private String username;
//     private String email;
//     private String role; // USER or ADMIN
// }

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String keycloakId;

    private String username;
    private String email;
    private String role; // USER or ADMIN

     /**
     * Thêm trường password để nhận từ request body.
     * @Transient: Báo cho JPA bỏ qua trường này, không tạo cột trong database.
     * @JsonProperty(access = ...WRITE_ONLY): Báo cho Jackson (thư viện JSON)
     * chỉ cho phép ghi dữ liệu vào trường này khi nhận request,
     * và KHÔNG BAO GIỜ gửi trường này ra trong response.
     */
    @Transient
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;

    // Constructors
    public User() {
    }

    public User(Long id, String keycloakId, String username, String email, String role) {
        this.id = id;
        this.keycloakId = keycloakId;
        this.username = username;
        this.email = email;
        this.role = role;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }
    
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getKeycloakId() {
        return keycloakId;
    }

    public void setKeycloakId(String keycloakId) {
        this.keycloakId = keycloakId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}