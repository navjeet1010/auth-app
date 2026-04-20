package com.navjeet.auth.controllers;

import com.navjeet.auth.dtos.UserDto;
import com.navjeet.auth.services.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private UserController userController;

    @Test
    void createUserReturnsCreatedStatus() {
        UserDto request = UserDto.builder().email("user@example.com").build();
        UserDto created = UserDto.builder().email("user@example.com").build();
        when(userService.createUser(request)).thenReturn(created);

        var response = userController.createUser(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertEquals(created, response.getBody());
    }

    @Test
    void getAllUsersReturnsOk() {
        List<UserDto> users = List.of(UserDto.builder().email("user@example.com").build());
        when(userService.getAllUsers()).thenReturn(users);

        var response = userController.getAllUsers();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(users, response.getBody());
    }

    @Test
    void deleteUserReturnsNoContent() {
        var response = userController.deleteUserById("123");

        verify(userService).deleteUser("123");
        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
    }
}
