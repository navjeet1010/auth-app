package com.navjeet.auth.controllers;

import com.navjeet.auth.dtos.LoginRequest;
import com.navjeet.auth.dtos.RefreshTokenRequest;
import com.navjeet.auth.dtos.UserDto;
import com.navjeet.auth.entities.RefreshToken;
import com.navjeet.auth.entities.User;
import com.navjeet.auth.mappers.UserMapper;
import com.navjeet.auth.repositories.RefreshTokenRepository;
import com.navjeet.auth.repositories.UserRepository;
import com.navjeet.auth.security.CookieService;
import com.navjeet.auth.security.JwtService;
import com.navjeet.auth.services.AuthService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private UserMapper userMapper;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private CookieService cookieService;

    @InjectMocks
    private AuthController authController;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void registerUserReturnsCreatedResponse() {
        UserDto request = UserDto.builder().email("user@example.com").build();
        UserDto created = UserDto.builder().email("user@example.com").build();
        when(authService.registerUser(request)).thenReturn(created);

        var response = authController.registerUser(request);

        assertEquals(201, response.getStatusCode().value());
        assertEquals(created, response.getBody());
    }

    @Test
    void loginReturnsTokensForAuthenticatedEnabledUser() {
        UUID userId = UUID.randomUUID();
        LoginRequest request = new LoginRequest("user@example.com", "password");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new UsernamePasswordAuthenticationToken("user@example.com", null, List.of());
        User user = User.builder().id(userId).email("user@example.com").enable(true).build();
        UserDto userDto = UserDto.builder().id(userId).email("user@example.com").build();

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(jwtService.getRefreshTtlSeconds()).thenReturn(600L);
        when(jwtService.getAccessTtlSeconds()).thenReturn(60L);
        when(jwtService.generateAccessToken(user)).thenReturn("access-token");
        when(jwtService.generateRefreshToken(eq(user), any(String.class))).thenReturn("refresh-token");
        when(userMapper.toDto(user)).thenReturn(userDto);

        var entity = authController.login(request, response);

        assertEquals(200, entity.getStatusCode().value());
        assertNotNull(entity.getBody());
        assertEquals("access-token", entity.getBody().accessToken());
        assertEquals("refresh-token", entity.getBody().refreshToken());
        verify(refreshTokenRepository).save(any(RefreshToken.class));
        verify(cookieService).attachRefreshTokenToCookie(response, "refresh-token", 600);
        verify(cookieService).addNoCacheHeaders(response);
    }

    @Test
    void loginRejectsDisabledUser() {
        UUID userId = UUID.randomUUID();
        LoginRequest request = new LoginRequest("user@example.com", "password");
        Authentication authentication = new UsernamePasswordAuthenticationToken("user@example.com", null);
        User user = User.builder().id(userId).email("user@example.com").enable(false).build();

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        DisabledException exception = assertThrows(DisabledException.class,
                () -> authController.login(request, new MockHttpServletResponse()));

        assertEquals("User account is disabled", exception.getMessage());
    }

    @Test
    void refreshTokenUsesBodyTokenAndRotatesStoredToken() {
        UUID userId = UUID.randomUUID();
        User user = User.builder().id(userId).email("user@example.com").enable(true).build();
        RefreshToken storedToken = RefreshToken.builder()
                .jti("stored-jti")
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .revoked(false)
                .build();
        UserDto userDto = UserDto.builder().id(userId).email("user@example.com").build();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();

        when(jwtService.isRefreshToken("refresh-token")).thenReturn(true);
        when(jwtService.getJti("refresh-token")).thenReturn("stored-jti");
        when(jwtService.getUserId("refresh-token")).thenReturn(userId);
        when(refreshTokenRepository.findByJti("stored-jti")).thenReturn(Optional.of(storedToken));
        when(jwtService.getRefreshTtlSeconds()).thenReturn(600L);
        when(jwtService.getAccessTtlSeconds()).thenReturn(60L);
        when(jwtService.generateAccessToken(user)).thenReturn("new-access-token");
        when(jwtService.generateRefreshToken(eq(user), any(String.class))).thenReturn("new-refresh-token");
        when(userMapper.toDto(user)).thenReturn(userDto);

        var entity = authController.refreshToken(new RefreshTokenRequest("refresh-token"), response, servletRequest);

        assertEquals(200, entity.getStatusCode().value());
        assertNotNull(entity.getBody());
        assertEquals("new-access-token", entity.getBody().accessToken());
        assertEquals("new-refresh-token", entity.getBody().refreshToken());
        assertEquals("stored-jti", storedToken.getJti());
        assertNotNull(storedToken.getReplacementJti());
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
        verify(cookieService).attachRefreshTokenToCookie(response, "new-refresh-token", 600);
        verify(cookieService).addNoCacheHeaders(response);
    }

    @Test
    void refreshTokenReadsCookieWhenBodyMissing() {
        UUID userId = UUID.randomUUID();
        User user = User.builder().id(userId).email("user@example.com").build();
        RefreshToken storedToken = RefreshToken.builder()
                .jti("cookie-jti")
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .revoked(false)
                .build();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new jakarta.servlet.http.Cookie("refresh-cookie", "cookie-refresh-token"));

        when(cookieService.getRefreshTokenCookieName()).thenReturn("refresh-cookie");
        when(jwtService.isRefreshToken("cookie-refresh-token")).thenReturn(true);
        when(jwtService.getJti("cookie-refresh-token")).thenReturn("cookie-jti");
        when(jwtService.getUserId("cookie-refresh-token")).thenReturn(userId);
        when(refreshTokenRepository.findByJti("cookie-jti")).thenReturn(Optional.of(storedToken));
        when(jwtService.getRefreshTtlSeconds()).thenReturn(600L);
        when(jwtService.getAccessTtlSeconds()).thenReturn(60L);
        when(jwtService.generateAccessToken(user)).thenReturn("access");
        when(jwtService.generateRefreshToken(eq(user), any(String.class))).thenReturn("refresh");
        when(userMapper.toDto(user)).thenReturn(UserDto.builder().email("user@example.com").build());

        var entity = authController.refreshToken(null, new MockHttpServletResponse(), request);

        assertEquals(200, entity.getStatusCode().value());
    }

    @Test
    void refreshTokenRejectsMissingToken() {
        BadCredentialsException exception = assertThrows(BadCredentialsException.class,
                () -> authController.refreshToken(null, new MockHttpServletResponse(), new MockHttpServletRequest()));

        assertEquals("Refresh token is required", exception.getMessage());
    }

    @Test
    void logoutRevokesStoredTokenAndClearsCookie() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        RefreshToken refreshToken = RefreshToken.builder()
                .jti("logout-jti")
                .revoked(false)
                .build();
        request.addHeader("X-Refresh-Token", "refresh-token");
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("user", null));

        when(jwtService.isRefreshToken("refresh-token")).thenReturn(true);
        when(jwtService.getJti("refresh-token")).thenReturn("logout-jti");
        when(refreshTokenRepository.findByJti("logout-jti")).thenReturn(Optional.of(refreshToken));

        var entity = authController.logout(request, response);

        assertEquals(204, entity.getStatusCode().value());
        assertTrue(refreshToken.isRevoked());
        verify(refreshTokenRepository).save(refreshToken);
        verify(cookieService).clearRefreshTokenCookie(response);
        verify(cookieService).addNoCacheHeaders(response);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
}
