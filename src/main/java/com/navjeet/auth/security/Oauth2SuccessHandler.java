package com.navjeet.auth.security;

import com.navjeet.auth.entities.Provider;
import com.navjeet.auth.entities.RefreshToken;
import com.navjeet.auth.entities.User;
import com.navjeet.auth.repositories.RefreshTokenRepository;
import com.navjeet.auth.repositories.UserRepository;
import com.navjeet.auth.services.CookieService;
import com.navjeet.auth.services.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Component
@AllArgsConstructor
public class Oauth2SuccessHandler implements AuthenticationSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(Oauth2SuccessHandler.class);

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String registrationId = getRegistrationId(authentication);
        User newUser = buildUser(registrationId, oAuth2User.getAttributes());

        if (newUser == null) {
            logger.warn("Unsupported OAuth2 provider: {}", registrationId);
            return;
        }

        User user = userRepository.findByEmail(newUser.getEmail())
                .orElseGet(() -> userRepository.save(newUser));
        issueRefreshToken(response, user);
        response.getWriter().write("Authentication successful");
    }

    private String getRegistrationId(Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken token) {
            return token.getAuthorizedClientRegistrationId();
        }

        return "unknown";
    }

    private User buildUser(String registrationId, Map<String, Object> attributes) {
        return switch (registrationId) {
            case "google" -> buildUser(
                    getAttribute(attributes, "email"),
                    getAttribute(attributes, "name"),
                    getAttribute(attributes, "sub"),
                    getAttribute(attributes, "picture"),
                    Provider.GOOGLE
            );
            case "github" -> buildUser(
                    getAttribute(attributes, "email"),
                    getAttribute(attributes, "login"),
                    getAttribute(attributes, "id"),
                    getAttribute(attributes, "avatar_url"),
                    Provider.GITHUB
            );
            default -> null;
        };
    }

    private User buildUser(String email, String name, String providerId, String image, Provider provider) {
        return User.builder()
                .email(email)
                .name(name)
                .providerId(providerId)
                .image(image)
                .provider(provider)
                .build();
    }

    private String getAttribute(Map<String, Object> attributes, String key) {
        return attributes.getOrDefault(key, "").toString();
    }

    private void issueRefreshToken(HttpServletResponse response, User user) throws IOException {
        String jti = UUID.randomUUID().toString();
        long refreshTtlSeconds = jwtService.getRefreshTtlSeconds();
        RefreshToken refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(refreshTtlSeconds))
                .revoked(false)
                .build();
        refreshTokenRepository.save(refreshTokenOb);

        String refreshTokenString = jwtService.generateRefreshToken(user, jti);
        cookieService.attachRefreshTokenToCookie(response, refreshTokenString, (int) refreshTtlSeconds);
    }
}
