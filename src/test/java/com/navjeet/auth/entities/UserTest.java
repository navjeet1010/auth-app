package com.navjeet.auth.entities;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class UserTest {

    @Test
    void getAuthoritiesMapsRolesToGrantedAuthorities() {
        User user = User.builder()
                .roles(Set.of(Role.builder().name("ROLE_USER").build(), Role.builder().name("ROLE_ADMIN").build()))
                .build();

        var authorities = user.getAuthorities();

        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_USER")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Test
    void lifecycleCallbacksMaintainTimestamps() {
        User user = User.builder().createdAt(null).updatedAt(null).build();

        user.onCreate();
        Instant createdAt = user.getCreatedAt();
        Instant updatedAt = user.getUpdatedAt();
        user.onUpdate();

        assertNotNull(createdAt);
        assertNotNull(updatedAt);
        assertEquals(createdAt, user.getCreatedAt());
        assertFalse(user.getUpdatedAt().isBefore(updatedAt));
    }
}
