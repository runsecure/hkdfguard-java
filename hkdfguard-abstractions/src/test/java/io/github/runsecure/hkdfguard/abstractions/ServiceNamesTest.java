package io.github.runsecure.hkdfguard.abstractions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class ServiceNamesTest {
    @ParameterizedTest
    @ValueSource(strings = {"a", "7", "my.service", "com.example.Orders2", "trailing."})
    void validNames_Pass(String name) {
        assertTrue(ServiceNames.isValid(name));
        assertNull(ServiceNames.getProblem(name));
        ServiceNames.requireValid(name, "name");
    }

    @Test
    void exactlyMaxLength_Passes_AndOneMoreFails() {
        assertEquals(128, ServiceNames.MAX_LENGTH);
        assertTrue(ServiceNames.isValid("a".repeat(ServiceNames.MAX_LENGTH)));

        var tooLong = "a".repeat(ServiceNames.MAX_LENGTH + 1);
        assertFalse(ServiceNames.isValid(tooLong));
        assertTrue(ServiceNames.getProblem(tooLong).contains("at most 128 characters; this one is 129"));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', nullValues = "NULL", value = {
            "NULL|required",
            "''|required",
            ".service|can't start with '.'",
            ".|can't start with '.'",
            "my..service|can't contain '..'",
            "my...service|can't contain '..'",
            "service..|can't contain '..'",
            "my-service|U+002D at position 2",
            "my service|U+0020 at position 2",
            "my_service|U+005F at position 2",
            "café|U+00E9 at position 3",
            "a/b|U+002F at position 1",
    })
    void invalidNames_FailWithTheReason(String name, String reason) {
        assertFalse(ServiceNames.isValid(name));
        assertTrue(ServiceNames.getProblem(name).contains(reason), ServiceNames.getProblem(name));
    }

    @Test
    void aNulCharacter_IsInvalid() {
        assertTrue(ServiceNames.getProblem("a\0b").contains("U+0000 at position 1"));
    }

    @Test
    void requireValid_ReportsTheParameterAndReason() {
        var npe = assertThrows(NullPointerException.class, () -> ServiceNames.requireValid(null, "serviceName"));
        assertEquals("serviceName", npe.getMessage());

        var ex = assertThrows(IllegalArgumentException.class, () -> ServiceNames.requireValid("a..b", "serviceName"));
        assertTrue(ex.getMessage().startsWith("serviceName: "));
        assertTrue(ex.getMessage().contains("can't contain '..'"));
    }
}
