package com.navjeet.auth.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Service
@Getter
public class CookieService {

    private final String refreshTokenCookieName;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookieSameSite;
    private final String cookieDomain;

    public CookieService(
            @Value("${security.jwt.refresh-token-cookie-name}") String refreshTokenCookieName,
            @Value("${security.jwt.cookie-http-only}") boolean cookieHttpOnly,
            @Value("${security.jwt.cookie-secure}") boolean cookieSecure,
            @Value("${security.jwt.cookie-same-site}") String cookieSameSite,
            @Value("${security.jwt.cookie-domain}") String cookieDomain

    ) {
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.cookieSameSite = cookieSameSite;
        this.cookieDomain = cookieDomain;
    }

    public void attachRefreshTokenToCookie(HttpServletResponse response, String refreshToken, int maxAge) {

        ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(refreshTokenCookieName, refreshToken)
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .sameSite(cookieSameSite)
                .path("/")
                .maxAge(maxAge);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            cookieBuilder.domain(cookieDomain);
        }

        ResponseCookie responseCookie = cookieBuilder.build();
        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());

    }

    public void clearRefreshTokenCookie(HttpServletResponse response) {
        ResponseCookie.ResponseCookieBuilder cookieBuilder = ResponseCookie.from(refreshTokenCookieName, "")
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .sameSite(cookieSameSite)
                .path("/")
                .maxAge(0);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            cookieBuilder.domain(cookieDomain);
        }

        ResponseCookie responseCookie = cookieBuilder.build();
        response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
    }

    public void addNoCacheHeaders(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
    }

}
