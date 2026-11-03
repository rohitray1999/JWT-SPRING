package com.example.jwtdemo.service;

import com.example.jwtdemo.exception.ApiException;
import jakarta.annotation.PostConstruct;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory user store. Real project me isko JPA repository se replace karo. */
@Service
public class UserService {

    public record AppUser(String username, String passwordHash, List<String> roles) {}

    private final Map<String, AppUser> users = new ConcurrentHashMap<>();
    private final PasswordEncoder encoder;

    public UserService(PasswordEncoder encoder) { this.encoder = encoder; }

    @PostConstruct
    void seed() {
        users.put("admin", new AppUser("admin", encoder.encode("admin123"), List.of("ROLE_USER", "ROLE_ADMIN")));
        users.put("user", new AppUser("user", encoder.encode("user123"), List.of("ROLE_USER")));
    }

    public AppUser register(String username, String rawPassword) {
        AppUser u = new AppUser(username, encoder.encode(rawPassword), List.of("ROLE_USER"));
        if (users.putIfAbsent(username, u) != null) {
            throw new ApiException(HttpStatus.CONFLICT, "Username already exists");
        }
        return u;
    }

    public AppUser authenticate(String username, String rawPassword) {
        AppUser u = users.get(username);
        if (u == null || !encoder.matches(rawPassword, u.passwordHash())) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }
        return u;
    }

    public AppUser find(String username) {
        AppUser u = users.get(username);
        if (u == null) throw new ApiException(HttpStatus.UNAUTHORIZED, "User not found");
        return u;
    }
}
