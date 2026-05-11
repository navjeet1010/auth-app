package com.navjeet.auth.security;

import com.navjeet.auth.entities.Provider;
import com.navjeet.auth.entities.RefreshToken;
import com.navjeet.auth.entities.User;
import com.navjeet.auth.repositories.RefreshTokenRepository;
import com.navjeet.auth.repositories.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@AllArgsConstructor
public class Oauth2SuccessHandler implements AuthenticationSuccessHandler {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private final RefreshTokenRepository refreshTokenRepository;



    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
        String registrationId = "unknown";
        if(authentication instanceof OAuth2AuthenticationToken token) {
            registrationId = token.getAuthorizedClientRegistrationId();
        }
        User user;
        switch (registrationId){
            case "google" -> {
                String googleId = oAuth2User.getAttributes().getOrDefault("sub", "").toString();
                String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
                String name = oAuth2User.getAttributes().getOrDefault("name", "").toString();
                User newUser = User.builder()
                        .email(email)
                        .name(name)
                        .providerId(googleId)
                        .image(oAuth2User.getAttributes().getOrDefault("picture", "default-profile.png").toString())
                        .provider(Provider.GOOGLE)
                        .build();
                user = userRepository.findByEmail(email).orElseGet(() -> userRepository.save(newUser));
                String jti = UUID.randomUUID().toString();
                RefreshToken refreshTokenOb = RefreshToken.builder()
                        .jti(jti)
                        .user(user)
                        .createdAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                        .revoked(false)
                        .build();
                System.out.println("RefreshToken " + refreshTokenOb);
                refreshTokenRepository.save(refreshTokenOb);
                String refreshTokenString = jwtService.generateRefreshToken(user, jti);
                cookieService.attachRefreshTokenToCookie(response, refreshTokenString, (int) jwtService.getRefreshTtlSeconds());
                response.getWriter().write("Authentication successful");

            }
            default -> System.out.println("Unsupported provider: " + registrationId);
        }

    }
}
