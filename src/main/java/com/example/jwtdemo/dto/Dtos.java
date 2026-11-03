package com.example.jwtdemo.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Map;

public class Dtos {
    public record RegisterRequest(@NotBlank String username, @NotBlank @Size(min = 6) String password) {}
    public record LoginRequest(@NotBlank String username, @NotBlank String password) {}
    public record RefreshRequest(@NotBlank String refreshToken) {}
    public record ValidateRequest(@NotBlank String token) {}
    public record LogoutRequest(String refreshToken) {}
    public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresInSeconds) {}
    public record ValidateResponse(boolean valid, String reason, Map<String, Object> claims) {}
}
