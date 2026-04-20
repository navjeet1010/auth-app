package com.navjeet.auth.services.impl;

import com.navjeet.auth.dtos.UserDto;
import com.navjeet.auth.services.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserService userService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthServiceImpl authService;

    @Test
    void registerUserEncodesPasswordBeforeDelegating() {
        UserDto userDto = UserDto.builder()
                .email("user@example.com")
                .password("plain-text")
                .build();
        UserDto createdUser = UserDto.builder().email("user@example.com").password("encoded").build();

        when(passwordEncoder.encode("plain-text")).thenReturn("encoded");
        when(userService.createUser(userDto)).thenReturn(createdUser);

        UserDto result = authService.registerUser(userDto);

        assertEquals("encoded", userDto.getPassword());
        assertEquals(createdUser, result);
        verify(passwordEncoder).encode("plain-text");
        verify(userService).createUser(userDto);
    }
}
