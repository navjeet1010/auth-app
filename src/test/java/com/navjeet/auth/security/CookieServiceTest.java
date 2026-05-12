package com.navjeet.auth.security;

import com.navjeet.auth.services.impl.CookieServiceImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.HttpHeaders.CACHE_CONTROL;
import static org.springframework.http.HttpHeaders.PRAGMA;
import static org.springframework.http.HttpHeaders.SET_COOKIE;

class CookieServiceTest {

    @Test
    void attachRefreshTokenAddsConfiguredCookieHeader() {
        CookieServiceImpl cookieService = new CookieServiceImpl("refresh", true, true, "Strict", "example.com");
        MockHttpServletResponse response = new MockHttpServletResponse();

        cookieService.attachRefreshTokenToCookie(response, "token-value", 3600);

        String header = response.getHeader(SET_COOKIE);
        Assertions.assertNotNull(header);
        assertTrue(header.contains("refresh=token-value"));
        assertTrue(header.contains("Max-Age=3600"));
        assertTrue(header.contains("HttpOnly"));
        assertTrue(header.contains("Secure"));
        assertTrue(header.contains("SameSite=Strict"));
        assertTrue(header.contains("Domain=example.com"));
    }

    @Test
    void clearRefreshTokenCookieExpiresCookieImmediately() {
        CookieServiceImpl cookieService = new CookieServiceImpl("refresh", true, false, "Lax", "");
        MockHttpServletResponse response = new MockHttpServletResponse();

        cookieService.clearRefreshTokenCookie(response);

        String header = response.getHeader(SET_COOKIE);
        Assertions.assertNotNull(header);
        assertTrue(header.contains("refresh="));
        assertTrue(header.contains("Max-Age=0"));
        assertTrue(header.contains("SameSite=Lax"));
    }

    @Test
    void addNoCacheHeadersSetsExpectedValues() {
        CookieServiceImpl cookieService = new CookieServiceImpl("refresh", true, false, "Lax", "");
        MockHttpServletResponse response = new MockHttpServletResponse();

        cookieService.addNoCacheHeaders(response);

        assertEquals("no-store, no-cache, must-revalidate, max-age=0", response.getHeader(CACHE_CONTROL));
        assertEquals("no-cache", response.getHeader(PRAGMA));
    }
}
