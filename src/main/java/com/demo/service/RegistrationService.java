package com.demo.service;

import com.demo.entity.User;
import com.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RegistrationService {

    private final KeycloakAdminService keycloakAdminService;
    private final UserRepository userRepository;

    @Autowired
    public RegistrationService(KeycloakAdminService keycloakAdminService, UserRepository userRepository) {
        this.keycloakAdminService = keycloakAdminService;
        this.userRepository = userRepository;
    }

    @Transactional
    public User registerNewUser(User userToRegister) { // THAY ĐỔI: Nhận và trả về User entity
        // Bước 1: Tạo user trên Keycloak và lấy về keycloakId
        String keycloakId = keycloakAdminService.createUser(userToRegister);

        // Bước 2: Cập nhật keycloakId vào chính đối tượng user vừa nhận được
        //add role
        keycloakAdminService.assignRoleToUser(keycloakId, userToRegister.getRole());

        userToRegister.setKeycloakId(keycloakId);
        userToRegister.setRole(userToRegister.getRole().toUpperCase());

        // Bước 3: Lưu đối tượng User hoàn chỉnh vào CSDL và trả về
        return userRepository.save(userToRegister);
    }
}