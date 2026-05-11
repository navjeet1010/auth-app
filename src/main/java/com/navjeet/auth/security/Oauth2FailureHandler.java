package com.navjeet.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.navjeet.auth.dtos.ApiError;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class Oauth2FailureHandler implements AuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(Oauth2FailureHandler.class);

    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException, ServletException {
        logger.info("OAuth2 authentication failed: {}", exception.getMessage());

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        var apiError = ApiError.of(
                HttpStatus.UNAUTHORIZED.value(),
                "OAuth2 Authentication Failed",
                exception.getMessage(),
                request.getRequestURI(),
                true
        );

        response.getWriter().write(objectMapper.writeValueAsString(apiError));
    }
}
