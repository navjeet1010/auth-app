package com.navjeet.auth.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ApiDocConfigTest {

    @Test
    void apiDocConfigDefinesOpenApiMetadata() {
        OpenAPIDefinition openApiDefinition = ApiDocConfig.class.getAnnotation(OpenAPIDefinition.class);

        assertNotNull(openApiDefinition);
        assertEquals("Authentication API", openApiDefinition.info().title());
        assertEquals("1.0", openApiDefinition.info().version());
        assertEquals("API for user authentication and authorization", openApiDefinition.info().description());
        assertEquals("Navjeet Singh", openApiDefinition.info().contact().name());
        assertEquals("navjeet.singh@xyz.com", openApiDefinition.info().contact().email());
        assertEquals("bearerAuth", openApiDefinition.security()[0].name());
    }

    @Test
    void apiDocConfigDefinesBearerJwtSecurityScheme() {
        SecurityScheme securityScheme = ApiDocConfig.class.getAnnotation(SecurityScheme.class);

        assertNotNull(securityScheme);
        assertEquals("bearerAuth", securityScheme.name());
        assertEquals(SecuritySchemeType.HTTP, securityScheme.type());
        assertEquals("bearer", securityScheme.scheme());
        assertEquals("JWT", securityScheme.bearerFormat());
    }

    @Test
    void apiDocConfigIsSpringConfiguration() {
        assertNotNull(ApiDocConfig.class.getAnnotation(Configuration.class));
    }
}
