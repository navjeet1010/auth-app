package com.navjeet.auth.dtos;

public record LoginRequest(
        String email,
        String password
) {

}
