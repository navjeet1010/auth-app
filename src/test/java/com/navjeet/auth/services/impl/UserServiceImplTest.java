package com.navjeet.auth.services.impl;

import com.navjeet.auth.dtos.UserDto;
import com.navjeet.auth.entities.Provider;
import com.navjeet.auth.entities.Role;
import com.navjeet.auth.entities.User;
import com.navjeet.auth.exceptions.ResourceNotFoundException;
import com.navjeet.auth.mappers.UserMapper;
import com.navjeet.auth.repositories.RoleRepository;
import com.navjeet.auth.repositories.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserMapper userMapper;

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private UserServiceImpl userService;

    @Test
    void createUserRejectsBlankEmail() {
        UserDto userDto = UserDto.builder().email(" ").build();

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> userService.createUser(userDto));

        assertEquals("Email is required", exception.getMessage());
        verify(userRepository, never()).save(any());
    }

    @Test
    void createUserRejectsDuplicateEmail() {
        UserDto userDto = UserDto.builder().email("user@example.com").build();
        when(userRepository.existsByEmail("user@example.com")).thenReturn(true);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> userService.createUser(userDto));

        assertEquals("User with given email already exists", exception.getMessage());
    }

    @Test
    void createUserUsesLocalProviderWhenMissing() {
        UserDto userDto = UserDto.builder().email("user@example.com").provider(null).build();
        User user = new User();
        user.setEmail("user@example.com");
        Role userRole = Role.builder().name("ROLE_USER").build();
        User savedUser = User.builder().email("user@example.com").provider(Provider.LOCAL).build();
        UserDto savedDto = UserDto.builder().email("user@example.com").provider(Provider.LOCAL).build();

        when(userRepository.existsByEmail("user@example.com")).thenReturn(false);
        when(userMapper.toEntity(userDto)).thenReturn(user);
        when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(userRole));
        when(userRepository.save(user)).thenReturn(savedUser);
        when(userMapper.toDto(savedUser)).thenReturn(savedDto);

        UserDto result = userService.createUser(userDto);

        assertEquals(Provider.LOCAL, user.getProvider());
        assertEquals(1, user.getRoles().size());
        assertEquals("ROLE_USER", user.getRoles().iterator().next().getName());
        assertEquals(savedDto, result);
    }

    @Test
    void getUserByEmailReturnsMappedUser() {
        User user = User.builder().email("user@example.com").build();
        UserDto userDto = UserDto.builder().email("user@example.com").build();
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(userMapper.toDto(user)).thenReturn(userDto);

        UserDto result = userService.getUserByEmail("user@example.com");

        assertEquals(userDto, result);
    }

    @Test
    void getUserByEmailThrowsWhenMissing() {
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        ResourceNotFoundException exception = assertThrows(ResourceNotFoundException.class,
                () -> userService.getUserByEmail("missing@example.com"));

        assertEquals("User not found with given email id", exception.getMessage());
    }

    @Test
    void updateUserUpdatesMutableFields() {
        UUID userId = UUID.randomUUID();
        User existingUser = User.builder()
                .id(userId)
                .email("old@example.com")
                .name("Old Name")
                .image("old.png")
                .provider(Provider.LOCAL)
                .password("old-password")
                .enable(false)
                .build();
        UserDto updateDto = UserDto.builder()
                .email("new@example.com")
                .name("New Name")
                .image("new.png")
                .provider(Provider.GOOGLE)
                .password("new-password")
                .enable(true)
                .build();
        UserDto mappedDto = UserDto.builder().email("new@example.com").name("New Name").build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
        when(userRepository.save(existingUser)).thenReturn(existingUser);
        when(userMapper.toDto(existingUser)).thenReturn(mappedDto);

        UserDto result = userService.updateUser(updateDto, userId.toString());

        assertEquals("new@example.com", existingUser.getEmail());
        assertEquals("New Name", existingUser.getName());
        assertEquals("new.png", existingUser.getImage());
        assertEquals(Provider.GOOGLE, existingUser.getProvider());
        assertEquals("new-password", existingUser.getPassword());
        assertEquals(mappedDto, result);
    }

    @Test
    void deleteUserDeletesResolvedEntity() {
        UUID userId = UUID.randomUUID();
        User user = User.builder().id(userId).build();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        userService.deleteUser(userId.toString());

        verify(userRepository).delete(user);
    }

    @Test
    void getUserByIdReturnsMappedUser() {
        UUID userId = UUID.randomUUID();
        User user = User.builder().id(userId).build();
        UserDto userDto = UserDto.builder().id(userId).build();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(userMapper.toDto(user)).thenReturn(userDto);

        UserDto result = userService.getUserById(userId.toString());

        assertEquals(userDto, result);
    }

    @Test
    void getAllUsersMapsRepositoryResults() {
        User first = User.builder().email("first@example.com").build();
        User second = User.builder().email("second@example.com").build();
        UserDto firstDto = UserDto.builder().email("first@example.com").build();
        UserDto secondDto = UserDto.builder().email("second@example.com").build();
        when(userRepository.findAll()).thenReturn(List.of(first, second));
        when(userMapper.toDto(first)).thenReturn(firstDto);
        when(userMapper.toDto(second)).thenReturn(secondDto);

        Iterable<UserDto> result = userService.getAllUsers();

        assertIterableEquals(List.of(firstDto, secondDto), result);
    }
}
