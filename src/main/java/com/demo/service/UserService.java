package com.demo.service;

import com.demo.entity.User;
import com.demo.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // Đăng ký user mới
    public User createUser(String username, String email, String role) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setRole(role); // ví dụ: ROLE_USER, ROLE_ADMIN
        return userRepository.save(user);
    }

    // Lấy tất cả user
    public List<User> findAll() {
        return userRepository.findAll();
    }

    // Lấy user theo username
    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    // Lưu (trường hợp update)
    public User save(User user) {
        return userRepository.save(user);
    }
}
