package com.navjeet.auth.services;

import com.navjeet.auth.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

import java.util.List;
import java.util.UUID;

public interface JwtService {

    long getAccessTtlSeconds();

    long getRefreshTtlSeconds();

    String generateAccessToken(User user);

    String generateRefreshToken(User user, String jti);

    Jws<Claims> parse(String token);

    boolean isAccessToken(String token);

    boolean isRefreshToken(String token);

    UUID getUserId(String token);

    String getJti(String token);

    List<String> getRoles(String token);

    String getEmail(String token);
}
