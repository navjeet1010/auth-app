package com.navjeet.auth.config;

public class AppConstants {
    public static final String[] AUTH_PUBLIC_URLS = {
            "/api/v1/auth/**",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html"
    };

    public static final String ADMIN_ROLE = "ADMIN";
    public static final String USER_ROLE = "USER";

}
