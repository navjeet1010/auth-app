package com.navjeet.auth.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Oauth2FailureHandlerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Oauth2FailureHandler handler = new Oauth2FailureHandler(objectMapper);

    @Test
    void onAuthenticationFailureWritesUnauthorizedApiError() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/google");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("oauth failed"));

        assertEquals(401, response.getStatus());
        assertEquals("application/json", response.getContentType());

        JsonNode body = objectMapper.readTree(response.getContentAsString());
        assertEquals(401, body.get("status").asInt());
        assertEquals("OAuth2 Authentication Failed", body.get("error").asText());
        assertEquals("oauth failed", body.get("message").asText());
        assertEquals("/login/oauth2/code/google", body.get("path").asText());
        assertTrue(body.get("timestamp").isNull());
    }
}
