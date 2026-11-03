package com.example.jwtdemo.controller;

import com.example.jwtdemo.dto.Dtos.*;
import com.example.jwtdemo.exception.ApiException;
import com.example.jwtdemo.security.JwtService;
import com.example.jwtdemo.security.TokenBlacklist;
import com.example.jwtdemo.service.UserService;
import com.example.jwtdemo.service.UserService.AppUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService users;
    private final JwtService jwt;
    private final TokenBlacklist blacklist;

    public AuthController(UserService users, JwtService jwt, TokenBlacklist blacklist) {
        this.users = users;
        this.jwt = jwt;
        this.blacklist = blacklist;
    }

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@Valid @RequestBody RegisterRequest req) {
        AppUser u = users.register(req.username(), req.password());
        return ResponseEntity.status(HttpStatus.CREATED).body(issue(u));
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest req) {
        return issue(users.authenticate(req.username(), req.password()));
    }

    /** Refresh token rotation: purana refresh token revoke, naya pair issue. */
    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest req) {
        Claims c = jwt.parseOfType(req.refreshToken(), JwtService.TYPE_REFRESH);
        if (blacklist.isRevoked(c.getId())) throw new JwtException("Refresh token has been revoked");
        AppUser u = users.find(c.getSubject());
        blacklist.revoke(c.getId(), c.getExpiration());
        return issue(u);
    }

    /** Kisi bhi token ko check karo (access ya refresh) - valid hai ya nahi, aur claims kya hain. */
    @PostMapping("/validate")
    public ValidateResponse validate(@Valid @RequestBody ValidateRequest req) {
        try {
            Claims c = jwt.parse(req.token());
            if (blacklist.isRevoked(c.getId())) {
                return new ValidateResponse(false, "Token has been revoked", null);
            }
            Map<String, Object> claims = new LinkedHashMap<>(c);
            return new ValidateResponse(true, null, claims);
        } catch (JwtException | IllegalArgumentException e) {
            return new ValidateResponse(false, e.getMessage(), null);
        }
    }

    /** Access token (header) + optional refresh token (body) dono revoke. */
    @PostMapping("/logout")
    public Map<String, String> logout(@RequestHeader("Authorization") String authHeader,
                                      @RequestBody(required = false) LogoutRequest body) {
        if (!authHeader.startsWith("Bearer ")) throw new ApiException(HttpStatus.BAD_REQUEST, "Bearer token required");
        Claims access = jwt.parseOfType(authHeader.substring(7), JwtService.TYPE_ACCESS);
        blacklist.revoke(access.getId(), access.getExpiration());
        if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()) {
            Claims refresh = jwt.parseOfType(body.refreshToken(), JwtService.TYPE_REFRESH);
            blacklist.revoke(refresh.getId(), refresh.getExpiration());
        }
        return Map.of("message", "Logged out");
    }

    private TokenResponse issue(AppUser u) {
        return new TokenResponse(
                jwt.generateAccessToken(u.username(), u.roles()),
                jwt.generateRefreshToken(u.username()),
                "Bearer",
                jwt.accessTtlSeconds());
    }
}
