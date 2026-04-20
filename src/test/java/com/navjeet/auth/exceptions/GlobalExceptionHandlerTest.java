package com.navjeet.auth.exceptions;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleAuthExceptionReturnsBadRequestApiError() {
        HttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/login");

        var response = handler.handleAuthException(new BadCredentialsException("bad creds"), request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assertions.assertNotNull(response.getBody());
        assertEquals("bad creds", response.getBody().message());
        assertEquals("/api/v1/auth/login", response.getBody().path());
    }

    @Test
    void handleResourceNotFoundExceptionReturnsNotFound() {
        var response = handler.handleResourceNotFoundException(new ResourceNotFoundException("missing"));

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        Assertions.assertNotNull(response.getBody());
        assertEquals("missing", response.getBody().message());
        assertEquals(404, response.getBody().statusCode());
    }

    @Test
    void handleIllegalArgumentExceptionReturnsBadRequest() {
        var response = handler.handleIllegalArgumentException(new IllegalArgumentException("bad argument"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        Assertions.assertNotNull(response.getBody());
        assertEquals("bad argument", response.getBody().message());
        assertEquals(400, response.getBody().statusCode());
    }
}
