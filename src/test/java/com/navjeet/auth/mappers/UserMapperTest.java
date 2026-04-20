package com.navjeet.auth.mappers;

import com.navjeet.auth.dtos.UserDto;
import com.navjeet.auth.entities.Provider;
import com.navjeet.auth.entities.User;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UserMapperTest {

    private final UserMapper userMapper = Mappers.getMapper(UserMapper.class);

    @Test
    void toDtoMapsCoreFields() {
        User user = User.builder()
                .email("user@example.com")
                .name("User")
                .provider(Provider.GITHUB)
                .build();

        UserDto dto = userMapper.toDto(user);

        assertEquals("user@example.com", dto.getEmail());
        assertEquals("User", dto.getName());
        assertEquals(Provider.GITHUB, dto.getProvider());
    }

    @Test
    void toEntityMapsCoreFields() {
        UserDto dto = UserDto.builder()
                .email("user@example.com")
                .name("User")
                .provider(Provider.GOOGLE)
                .build();

        User user = userMapper.toEntity(dto);

        assertEquals("user@example.com", user.getEmail());
        assertEquals("User", user.getName());
        assertEquals(Provider.GOOGLE, user.getProvider());
    }
}
