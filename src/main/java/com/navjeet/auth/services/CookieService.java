package com.navjeet.auth.services;

import jakarta.servlet.http.HttpServletResponse;

public interface CookieService {

    String getRefreshTokenCookieName();

    void attachRefreshTokenToCookie(HttpServletResponse response, String refreshToken, int maxAge);

    void clearRefreshTokenCookie(HttpServletResponse response);

    void addNoCacheHeaders(HttpServletResponse response);
}
