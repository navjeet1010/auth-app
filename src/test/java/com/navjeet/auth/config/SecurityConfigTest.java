package com.navjeet.auth.config;

import com.navjeet.auth.security.JwtAuthenticationFilter;
import com.navjeet.auth.security.Oauth2FailureHandler;
import com.navjeet.auth.security.Oauth2SuccessHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecurityConfigTest {

    @Mock
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Mock
    private Oauth2SuccessHandler oauth2SuccessHandler;

    @Mock
    private Oauth2FailureHandler oauth2FailureHandler;

    @Mock
    private AuthenticationConfiguration authenticationConfiguration;

    @Mock
    private AuthenticationManager authenticationManager;

    @Test
    void passwordEncoderProducesMatchingHashes() {
        SecurityConfig securityConfig = new SecurityConfig(jwtAuthenticationFilter, oauth2SuccessHandler, oauth2FailureHandler);

        PasswordEncoder passwordEncoder = securityConfig.passwordEncoder();
        String encoded = passwordEncoder.encode("secret");

        assertNotEquals("secret", encoded);
        assertTrue(passwordEncoder.matches("secret", encoded));
    }

    @Test
    void authenticationManagerDelegatesToAuthenticationConfiguration() throws Exception {
        SecurityConfig securityConfig = new SecurityConfig(jwtAuthenticationFilter, oauth2SuccessHandler, oauth2FailureHandler);
        when(authenticationConfiguration.getAuthenticationManager()).thenReturn(authenticationManager);

        AuthenticationManager result = securityConfig.authenticationManager(authenticationConfiguration);

        assertSame(authenticationManager, result);
    }
}
