package com.navjeet.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.navjeet.auth.dtos.ApiError;
import com.navjeet.auth.security.JwtAuthenticationFilter;
import com.navjeet.auth.security.Oauth2FailureHandler;
import com.navjeet.auth.security.Oauth2SuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.navjeet.auth.config.AppConstants.AUTH_PUBLIC_URLS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final Oauth2SuccessHandler oauth2SuccessHandler;
    private final Oauth2FailureHandler oauth2FailureHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(smc -> smc.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers(AUTH_PUBLIC_URLS).permitAll()
                                .requestMatchers(HttpMethod.GET).hasRole(AppConstants.USER_ROLE)
                                .requestMatchers("/api/v1/users/**").hasRole(AppConstants.ADMIN_ROLE)
                                .anyRequest()
                                .authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(oauth2SuccessHandler)
                        .failureHandler(oauth2FailureHandler))
                .exceptionHandling(ex ->
                        ex.authenticationEntryPoint((request,
                                                     response,
                                                     authException) -> {
                                    response.setStatus(401);
                                    response.setContentType("application/json");
                                    String message = "Unauthorized access: " + authException.getMessage();
                                    String error = (String) request.getAttribute("error");
                                    if (error != null) {
                                        message = error;
                                    }
                                    var apiError = ApiError.of(HttpStatus.UNAUTHORIZED.value(), "Unauthorized Access", message, request.getRequestURI(), true);
                                    ObjectMapper objectMapper = new ObjectMapper();
                                    response.getWriter().write(objectMapper.writeValueAsString(apiError));
                                }

                        ).accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(403);
                            response.setContentType("application/json");
                            String message = "Forbidden access: " + accessDeniedException.getMessage();
                            String error = (String) request.getAttribute("error");
                            if (error != null) {
                                message = error;
                            }
                            var apiError = ApiError.of(HttpStatus.FORBIDDEN.value(), "Forbidden Access", message, request.getRequestURI(), true);
                            ObjectMapper objectMapper = new ObjectMapper();
                            response.getWriter().write(objectMapper.writeValueAsString(apiError));
                        })

                ).addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}
