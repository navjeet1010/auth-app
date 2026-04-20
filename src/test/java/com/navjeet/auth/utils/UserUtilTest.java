package com.navjeet.auth.utils;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class UserUtilTest {

    @Test
    void parseUuidReturnsParsedUuid() {
        UUID uuid = UUID.randomUUID();

        assertEquals(uuid, UserUtil.parseUUID(uuid.toString()));
    }

    @Test
    void parseUuidThrowsForInvalidValue() {
        assertThrows(IllegalArgumentException.class, () -> UserUtil.parseUUID("invalid-uuid"));
    }
}
