package com.navjeet.auth.services.impl;

import com.navjeet.auth.config.AppConstants;
import com.navjeet.auth.dtos.UserDto;
import com.navjeet.auth.entities.Provider;
import com.navjeet.auth.entities.Role;
import com.navjeet.auth.entities.User;
import com.navjeet.auth.exceptions.ResourceNotFoundException;
import com.navjeet.auth.mappers.UserMapper;
import com.navjeet.auth.repositories.RoleRepository;
import com.navjeet.auth.repositories.UserRepository;
import com.navjeet.auth.services.UserService;
import com.navjeet.auth.utils.UserUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final RoleRepository roleRepository;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        if (userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }
        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException("User with given email already exists");
        }

        User user = userMapper.toEntity(userDto);
        user.setProvider(userDto.getProvider() != null ? userDto.getProvider() : Provider.LOCAL);

        Role role = roleRepository.findByName("ROLE_"+ AppConstants.USER_ROLE).orElse(null);
        user.getRoles().add(role);

        User savedUser = userRepository.save(user);
        return userMapper.toDto(savedUser);
    }

    @Override
    public UserDto getUserByEmail(String email) {
        User user = userRepository
                .findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with given email id"));
        return userMapper.toDto(user);
    }

    @Override
    @Transactional
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uId = UserUtil.parseUUID(userId);
        User existingUser = userRepository
                .findById(uId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with given id"));

        if (userDto.getName() != null) existingUser.setName(userDto.getName());
        if (userDto.getImage() != null) existingUser.setImage(userDto.getImage());
        if (userDto.getProvider() != null) existingUser.setProvider(userDto.getProvider());
        if (userDto.getPassword() != null) existingUser.setPassword(userDto.getPassword());
        if (userDto.getEmail() != null) existingUser.setEmail(userDto.getEmail());

        existingUser.setEnable(userDto.isEnable());

        User updatedUser = userRepository.save(existingUser);
        return userMapper.toDto(updatedUser);
    }

    @Override
    public void deleteUser(String userId) {
        UUID uId = UserUtil.parseUUID(userId);
        User user = userRepository.findById(uId).orElseThrow(() -> new ResourceNotFoundException("User not found with given id"));
        userRepository.delete(user);
    }

    @Override
    public UserDto getUserById(String userId) {
        User user = userRepository.findById(UserUtil.parseUUID(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found with given id"));
        return userMapper.toDto(user);
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {
        return userRepository
                .findAll()
                .stream()
                .map(userMapper::toDto)
                .toList();
    }
}
