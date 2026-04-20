package com.navjeet.auth.security;

import com.navjeet.auth.entities.Role;
import com.navjeet.auth.entities.User;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtServiceTest {

    private static final String SECRET = "0123456789012345678901234567890123456789012345678901234567890123";

    @Test
    void constructorRejectsShortSecret() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new JwtService("short-secret", 60, 120, "issuer"));

        assertEquals("JWT secret is invalid. It must be at least 64 characters long.", exception.getMessage());
    }

    @Test
    void accessTokenContainsExpectedClaims() {
        JwtService jwtService = new JwtService(SECRET, 60, 120, "issuer");
        UUID userId = UUID.randomUUID();
        User user = User.builder()
                .id(userId)
                .email("user@example.com")
                .roles(Set.of(Role.builder().name("ROLE_USER").build()))
                .build();

        String token = jwtService.generateAccessToken(user);

        assertTrue(jwtService.isAccessToken(token));
        assertFalse(jwtService.isRefreshToken(token));
        assertEquals(userId, jwtService.getUserId(token));
        assertEquals("user@example.com", jwtService.getEmail(token));
        assertEquals(Set.of("ROLE_USER"), Set.copyOf(jwtService.getRoles(token)));
    }

    @Test
    void refreshTokenContainsExpectedClaims() {
        JwtService jwtService = new JwtService(SECRET, 60, 120, "issuer");
        UUID userId = UUID.randomUUID();
        User user = User.builder().id(userId).email("user@example.com").build();

        String token = jwtService.generateRefreshToken(user, "refresh-jti");

        assertTrue(jwtService.isRefreshToken(token));
        assertFalse(jwtService.isAccessToken(token));
        assertEquals("refresh-jti", jwtService.getJti(token));
        assertEquals(userId, jwtService.getUserId(token));
        assertEquals(0, jwtService.getRoles(token).size());
    }
}
