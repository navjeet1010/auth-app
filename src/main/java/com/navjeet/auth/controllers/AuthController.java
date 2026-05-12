package com.navjeet.auth.controllers;

import com.navjeet.auth.dtos.LoginRequest;
import com.navjeet.auth.dtos.RefreshTokenRequest;
import com.navjeet.auth.dtos.TokenResponse;
import com.navjeet.auth.dtos.UserDto;
import com.navjeet.auth.entities.RefreshToken;
import com.navjeet.auth.entities.User;
import com.navjeet.auth.mappers.UserMapper;
import com.navjeet.auth.repositories.RefreshTokenRepository;
import com.navjeet.auth.repositories.UserRepository;
import com.navjeet.auth.services.CookieService;
import com.navjeet.auth.services.JwtService;
import com.navjeet.auth.services.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {

    private final AuthService authService;

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final UserMapper userMapper;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;

    private Authentication authenticate(LoginRequest loginRequest) {
        try {
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));

        } catch (Exception e) {
            throw new BadCredentialsException("Invalid email or password!!");

        }
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {

        Authentication authentication= authenticate(loginRequest);
        User user = userRepository.findByEmail(loginRequest.email()).orElseThrow(() -> new BadCredentialsException("User not found with given email id"));
        if (!user.isEnable() || !authentication.isAuthenticated()) {
            throw new DisabledException("User account is disabled");
        }

        String jti = UUID.randomUUID().toString();
        var refreshTokenObject = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshTokenObject);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenObject.getJti());

        cookieService.attachRefreshTokenToCookie(response, refreshToken, (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoCacheHeaders(response);

        TokenResponse tokenResponse = TokenResponse.of(accessToken, refreshToken, jwtService.getAccessTtlSeconds(), userMapper.toDto(user));
        return ResponseEntity.ok(tokenResponse);

    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestBody(required = false) RefreshTokenRequest refreshTokenRequest, HttpServletResponse response, HttpServletRequest request) {
        String refreshToken = readRefreshTokenFromRequest(refreshTokenRequest, request).orElseThrow(() -> new BadCredentialsException("Refresh token is required"));

        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new BadCredentialsException("Invalid refresh token");
        }
        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);
        RefreshToken storedRefreshToken = refreshTokenRepository.findByJti(jti).orElseThrow(() -> new BadCredentialsException("Refresh token not found in database"));

        if (storedRefreshToken.isRevoked()) {
            throw new BadCredentialsException("Refresh token is revoked");
        }

        if (storedRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token is expired");
        }

        if (!storedRefreshToken.getUser().getId().equals(userId)) {
            throw new BadCredentialsException("Refresh token does not belong to the expected user");
        }

        storedRefreshToken.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        storedRefreshToken.setReplacementJti(newJti);
        refreshTokenRepository.save(storedRefreshToken);

        User user = storedRefreshToken.getUser();
        RefreshToken newRefreshTokenObj = RefreshToken.builder()
                .jti(newJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();

        refreshTokenRepository.save(newRefreshTokenObj);
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user, newJti);

        cookieService.attachRefreshTokenToCookie(response, newRefreshToken, (int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoCacheHeaders(response);
        return ResponseEntity.ok(TokenResponse.of(newAccessToken, newRefreshToken, jwtService.getAccessTtlSeconds(), userMapper.toDto(user)));

    }

    private Optional<String> readRefreshTokenFromRequest(RefreshTokenRequest refreshTokenRequest, HttpServletRequest request) {
        if (refreshTokenRequest != null && refreshTokenRequest.refreshToken() != null && !refreshTokenRequest.refreshToken().isBlank()) {
            return Optional.of(refreshTokenRequest.refreshToken());
        }

        if (request.getCookies() != null) {
            return Arrays.stream(request.getCookies())
                    .filter(cookie -> cookie.getName().equals(cookieService.getRefreshTokenCookieName()))
                    .map(Cookie::getValue)
                    .filter(value -> !value.isBlank())
                    .findFirst();
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer", 0, 7)) {
            String token = authHeader.substring(7).trim();
            if (!token.isBlank()) {
                try {
                    if (jwtService.isRefreshToken(token)) {
                        return Optional.of(token);
                    }
                } catch (Exception ignore) {

                }
            }
        }

        String refreshHeader = request.getHeader("X-Refresh-Token");
        if (refreshHeader != null && !refreshHeader.isBlank()) {
            return Optional.of(refreshHeader.trim());
        }

        return Optional.empty();

    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        Optional<String> refreshTokenOpt = readRefreshTokenFromRequest(null, request);
        refreshTokenOpt.ifPresent(refreshToken -> {
            try {
                if (jwtService.isRefreshToken(refreshToken)) {
                    String jti = jwtService.getJti(refreshToken);
                    refreshTokenRepository.findByJti(jti).ifPresent(token -> {
                        token.setRevoked(true);
                        refreshTokenRepository.save(token);
                    });
                }
            } catch (Exception ignore) {

            }

        });

        cookieService.clearRefreshTokenCookie(response);
        cookieService.addNoCacheHeaders(response);
        SecurityContextHolder.clearContext();
        return ResponseEntity.noContent().build();
    }
}
