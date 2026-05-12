package com.navjeet.auth.services.impl;

import com.navjeet.auth.entities.Role;
import com.navjeet.auth.entities.User;
import com.navjeet.auth.services.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Getter
@Setter
public class JwtServiceImpl implements JwtService {

    private final SecretKey key;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

    public JwtServiceImpl(@Value("${security.jwt.secret}") String secret, @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds, @Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds, @Value("${security.jwt.issuer}") String issuer) {

        if (secret == null || secret.length() < 64) {
            throw new IllegalArgumentException("JWT secret is invalid. It must be at least 64 characters long.");
        }
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }

    @Override
    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        List<String> roles = user.getRoles() == null ? List.of() : user.getRoles().stream().map(Role::getName).toList();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getId().toString())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTtlSeconds)))
                .claims(Map.of("email", user.getEmail(), "roles", roles, "typ", "access"))
                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }

    @Override
    public String generateRefreshToken(User user, String jti) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(jti)
                .subject(user.getId().toString()).issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(refreshTtlSeconds)))
                .claim("typ", "refresh")
                .signWith(key, Jwts.SIG.HS512)
                .compact();
    }

    @Override
    public Jws<Claims> parse(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
    }

    @Override
    public boolean isAccessToken(String token) {
        Claims claims = parse(token).getPayload();
        return "access".equals(claims.get("typ"));
    }

    @Override
    public boolean isRefreshToken(String token) {
        Claims claims = parse(token).getPayload();
        return "refresh".equals(claims.get("typ"));
    }

    @Override
    public UUID getUserId(String token) {
        Claims claims = parse(token).getPayload();
        return UUID.fromString(claims.getSubject());
    }

    @Override
    public String getJti(String token) {
        return parse(token).getPayload().getId();
    }

    @Override
    public List<String> getRoles(String token) {
        Claims claims = parse(token).getPayload();
        List<?> rawRoles = claims.get("roles", List.class);

        return rawRoles == null ? List.of() : rawRoles.stream().map(Object::toString).toList();
    }

    @Override
    public String getEmail(String token) {
        Claims c = parse(token).getPayload();
        return (String) c.get("email");
    }

}
