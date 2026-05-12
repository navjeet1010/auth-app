package com.navjeet.auth.security;

import com.navjeet.auth.entities.Role;
import com.navjeet.auth.entities.User;
import com.navjeet.auth.repositories.UserRepository;
import com.navjeet.auth.services.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private JwtAuthenticationFilter filter;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterSetsAuthenticationForValidAccessToken() throws Exception {
        UUID userId = UUID.randomUUID();
        String token = "access-token";
        User user = User.builder()
                .id(userId)
                .email("user@example.com")
                .enable(true)
                .roles(Set.of(Role.builder().name("ROLE_USER").build()))
                .build();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        Claims claims = mock(Claims.class);
        @SuppressWarnings("unchecked")
        Jws<Claims> jws = (Jws<Claims>) mock(Jws.class);

        when(jwtService.isAccessToken(token)).thenReturn(true);
        when(jwtService.parse(token)).thenReturn(jws);
        when(jws.getPayload()).thenReturn(claims);
        when(claims.getSubject()).thenReturn(userId.toString());
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        filter.doFilter(request, response, new MockFilterChain());

        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertEquals("user@example.com", authentication.getPrincipal());
        assertTrue(authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
    }

    @Test
    void doFilterAddsErrorAttributeForExpiredToken() throws Exception {
        String token = "expired-token";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);

        when(jwtService.isAccessToken(token)).thenReturn(true);
        when(jwtService.parse(token)).thenThrow(new ExpiredJwtException(null, null, "expired"));

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertEquals("Token Expired", request.getAttribute("error"));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void doFilterSkipsNonAccessTokens() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer refresh-token");

        when(jwtService.isAccessToken("refresh-token")).thenReturn(false);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verifyNoInteractions(userRepository);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void shouldNotFilterAuthEndpoints() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/login");

        assertTrue(filter.shouldNotFilter(request));
    }
}
