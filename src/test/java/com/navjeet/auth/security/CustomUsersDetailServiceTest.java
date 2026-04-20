package com.navjeet.auth.security;

import com.navjeet.auth.entities.User;
import com.navjeet.auth.repositories.UserRepository;
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
class CustomUsersDetailServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUsersDetailService customUsersDetailService;

    @Test
    void loadUserByUsernameReturnsUserWhenPresent() {
        User user = User.builder().email("user@example.com").build();
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        assertEquals(user, customUsersDetailService.loadUserByUsername("user@example.com"));
    }

    @Test
    void loadUserByUsernameThrowsWhenMissing() {
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        UsernameNotFoundException exception = assertThrows(UsernameNotFoundException.class,
                () -> customUsersDetailService.loadUserByUsername("missing@example.com"));

        assertEquals("missing@example.com", exception.getMessage());
    }
}
