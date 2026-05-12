package com.navjeet.auth.mappers;

import com.navjeet.auth.dtos.UserDto;
import com.navjeet.auth.entities.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserDto toDto(User user);

    @Mapping(target = "providerId", ignore = true)
    User toEntity(UserDto userDto);
}
