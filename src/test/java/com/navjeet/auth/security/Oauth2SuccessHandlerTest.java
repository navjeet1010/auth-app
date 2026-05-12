package com.navjeet.auth.security;

import com.navjeet.auth.entities.Provider;
import com.navjeet.auth.entities.RefreshToken;
import com.navjeet.auth.entities.User;
import com.navjeet.auth.repositories.RefreshTokenRepository;
import com.navjeet.auth.repositories.UserRepository;
import com.navjeet.auth.services.CookieService;
import com.navjeet.auth.services.JwtService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class Oauth2SuccessHandlerTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private CookieService cookieService;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private Oauth2SuccessHandler handler;

    @Test
    void onAuthenticationSuccessCreatesGoogleUserAndIssuesRefreshToken() throws Exception {
        User savedUser = User.builder()
                .id(UUID.randomUUID())
                .email("user@example.com")
                .name("Test User")
                .provider(Provider.GOOGLE)
                .providerId("google-sub")
                .build();
        OAuth2AuthenticationToken authentication = googleAuthentication();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        when(jwtService.getRefreshTtlSeconds()).thenReturn(3600L);
        when(jwtService.generateRefreshToken(eq(savedUser), anyString())).thenReturn("refresh-token");

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, authentication);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User newUser = userCaptor.getValue();
        assertEquals("user@example.com", newUser.getEmail());
        assertEquals("Test User", newUser.getName());
        assertEquals("google-sub", newUser.getProviderId());
        assertEquals("https://example.com/avatar.png", newUser.getImage());
        assertEquals(Provider.GOOGLE, newUser.getProvider());

        ArgumentCaptor<RefreshToken> refreshTokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(refreshTokenCaptor.capture());
        RefreshToken refreshToken = refreshTokenCaptor.getValue();
        assertNotNull(refreshToken.getJti());
        assertSame(savedUser, refreshToken.getUser());
        assertNotNull(refreshToken.getCreatedAt());
        assertNotNull(refreshToken.getExpiresAt());
        assertFalse(refreshToken.isRevoked());

        verify(jwtService).generateRefreshToken(eq(savedUser), eq(refreshToken.getJti()));
        verify(cookieService).attachRefreshTokenToCookie(response, "refresh-token", 3600);
        assertEquals("Authentication successful", response.getContentAsString());
    }

    @Test
    void onAuthenticationSuccessUsesExistingGoogleUser() throws Exception {
        User existingUser = User.builder()
                .id(UUID.randomUUID())
                .email("user@example.com")
                .name("Existing User")
                .provider(Provider.GOOGLE)
                .providerId("existing-sub")
                .build();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(existingUser));
        when(jwtService.getRefreshTtlSeconds()).thenReturn(7200L);
        when(jwtService.generateRefreshToken(eq(existingUser), anyString())).thenReturn("existing-refresh-token");

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, googleAuthentication());

        verify(userRepository, never()).save(any(User.class));

        ArgumentCaptor<RefreshToken> refreshTokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(refreshTokenCaptor.capture());
        assertSame(existingUser, refreshTokenCaptor.getValue().getUser());

        verify(cookieService).attachRefreshTokenToCookie(response, "existing-refresh-token", 7200);
        assertEquals("Authentication successful", response.getContentAsString());
    }

    @Test
    void onAuthenticationSuccessCreatesGithubUserAndIssuesRefreshToken() throws Exception {
        User savedUser = User.builder()
                .id(UUID.randomUUID())
                .email("github@example.com")
                .name("github-login")
                .provider(Provider.GITHUB)
                .providerId("12345")
                .build();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(userRepository.findByEmail("github@example.com")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        when(jwtService.getRefreshTtlSeconds()).thenReturn(3600L);
        when(jwtService.generateRefreshToken(eq(savedUser), anyString())).thenReturn("github-refresh-token");

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, githubAuthentication());

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User newUser = userCaptor.getValue();
        assertEquals("github@example.com", newUser.getEmail());
        assertEquals("github-login", newUser.getName());
        assertEquals("12345", newUser.getProviderId());
        assertEquals("https://example.com/github-avatar.png", newUser.getImage());
        assertEquals(Provider.GITHUB, newUser.getProvider());

        ArgumentCaptor<RefreshToken> refreshTokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(refreshTokenCaptor.capture());
        RefreshToken refreshToken = refreshTokenCaptor.getValue();
        assertNotNull(refreshToken.getJti());
        assertSame(savedUser, refreshToken.getUser());

        verify(jwtService).generateRefreshToken(eq(savedUser), eq(refreshToken.getJti()));
        verify(cookieService).attachRefreshTokenToCookie(response, "github-refresh-token", 3600);
        assertEquals("Authentication successful", response.getContentAsString());
    }

    @Test
    void onAuthenticationSuccessIgnoresUnsupportedProvider() throws Exception {
        DefaultOAuth2User oauth2User = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                Map.of("sub", "provider-user"),
                "sub"
        );
        OAuth2AuthenticationToken authentication =
                new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "facebook");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, authentication);

        verifyNoInteractions(userRepository, refreshTokenRepository, jwtService, cookieService);
        assertEquals("", response.getContentAsString());
    }

    private OAuth2AuthenticationToken googleAuthentication() {
        return authentication("google", "sub", Map.of(
                "sub", "google-sub",
                "email", "user@example.com",
                "name", "Test User",
                "picture", "https://example.com/avatar.png"
        ));
    }

    private OAuth2AuthenticationToken githubAuthentication() {
        return authentication("github", "id", Map.of(
                "id", 12345,
                "email", "github@example.com",
                "login", "github-login",
                "avatar_url", "https://example.com/github-avatar.png"
        ));
    }

    private OAuth2AuthenticationToken authentication(String registrationId, String nameAttributeKey, Map<String, Object> attributes) {
        DefaultOAuth2User oauth2User = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                attributes,
                nameAttributeKey
        );

        return new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), registrationId);
    }
}
