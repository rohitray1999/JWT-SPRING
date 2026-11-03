package com.example.jwtdemo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
public class JwtService {

    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_REFRESH = "refresh";

    private final SecretKey key;
    private final String issuer;
    private final long accessMs;
    private final long refreshMs;

    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.issuer}") String issuer,
                      @Value("${jwt.access-expiration-ms}") long accessMs,
                      @Value("${jwt.refresh-expiration-ms}") long refreshMs) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        this.issuer = issuer;
        this.accessMs = accessMs;
        this.refreshMs = refreshMs;
    }

    public String generateAccessToken(String username, List<String> roles) {
        return build(username, roles, TYPE_ACCESS, accessMs);
    }

    public String generateRefreshToken(String username) {
        return build(username, List.of(), TYPE_REFRESH, refreshMs);
    }

    private String build(String username, List<String> roles, String type, long ttlMs) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())   // jti - revoke karne ke kaam aata hai
                .issuer(issuer)
                .subject(username)
                .claim("roles", roles)
                .claim("type", type)
                .issuedAt(new Date(now))
                .expiration(new Date(now + ttlMs))
                .signWith(key)
                .compact();
    }

    /** Signature, expiry aur issuer verify karke Claims deta hai. Fail hone par JwtException. */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .requireIssuer(issuer)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Claims parseOfType(String token, String expectedType) {
        Claims c = parse(token);
        if (!expectedType.equals(c.get("type", String.class))) {
            throw new JwtException("Wrong token type, expected " + expectedType);
        }
        return c;
    }

    public long accessTtlSeconds() { return accessMs / 1000; }
}
