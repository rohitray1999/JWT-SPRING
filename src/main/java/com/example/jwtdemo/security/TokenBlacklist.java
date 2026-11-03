package com.example.jwtdemo.security;

import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Revoked token IDs (jti). Multi-instance deployment me Redis use karo. */
@Component
public class TokenBlacklist {

    private final Map<String, Long> revoked = new ConcurrentHashMap<>();

    public void revoke(String jti, Date expiresAt) {
        purgeExpired();
        revoked.put(jti, expiresAt.getTime());
    }

    public boolean isRevoked(String jti) {
        return revoked.containsKey(jti);
    }

    private void purgeExpired() {
        long now = System.currentTimeMillis();
        revoked.values().removeIf(exp -> exp < now);
    }
}
