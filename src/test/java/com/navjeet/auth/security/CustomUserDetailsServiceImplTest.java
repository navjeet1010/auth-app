package com.navjeet.auth.security;

import com.navjeet.auth.entities.User;
import com.navjeet.auth.repositories.UserRepository;
import com.navjeet.auth.services.impl.CustomUserDetailsServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUserDetailsServiceImpl customUserDetailsService;

    @Test
    void loadUserByUsernameReturnsUserWhenPresent() {
        User user = User.builder().email("user@example.com").build();
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        assertEquals(user, customUserDetailsService.loadUserByUsername("user@example.com"));
    }

    @Test
    void loadUserByUsernameThrowsWhenMissing() {
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        UsernameNotFoundException exception = assertThrows(UsernameNotFoundException.class,
                () -> customUserDetailsService.loadUserByUsername("missing@example.com"));

        assertEquals("missing@example.com", exception.getMessage());
    }
}
