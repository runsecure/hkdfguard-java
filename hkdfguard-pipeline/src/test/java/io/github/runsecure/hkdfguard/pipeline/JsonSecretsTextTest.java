package io.github.runsecure.hkdfguard.pipeline;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The JSON object of secrets, byte for byte as .NET's indented, relaxed Utf8JsonWriter writes it. */
class JsonSecretsTextTest {
    private static String text(Map<String, String> secrets) {
        return new String(JsonSecretsText.of(secrets), StandardCharsets.UTF_8);
    }

    @Test
    void members_AreIndentedTwoSpaces_OnePerLine_WithNoLineEndingAfterTheBrace() {
        var secrets = new LinkedHashMap<String, String>();
        secrets.put("api-key", "enc::v1::ab+/cd==");
        secrets.put("db", "enc::v1::ef==");
        var n = System.lineSeparator();

        assertEquals("{" + n + "  \"api-key\": \"enc::v1::ab+/cd==\"," + n + "  \"db\": \"enc::v1::ef==\"" + n + "}", text(secrets));
    }

    @Test
    void noMembers_IsAnEmptyObject() {
        assertEquals("{}", text(Map.of()));
    }

    @Test
    void escaping_IsDotNetsRelaxedEncoders() {
        // What .NET 10's Utf8JsonWriter writes for this text with JavaScriptEncoder.UnsafeRelaxedJsonEscaping.
        var input = "\u0001\u001f\u007f  ﻿🔑\u0080\u009f�￾\b\t\"\\/<>&'+`é\f\n\r͸";
        var expected = "\"\\u0001\\u001F\\u007F\\u2028\\u00A0\\uFEFF\\uD83D\\uDD11\\u0080\\u009F�\\uFFFE\\b\\t\\\"\\\\/<>&'+`é"
                + "\\f\\n\\r\\uE000\\u0378\"";

        var json = new StringBuilder();
        JsonSecretsText.string(json, input);

        assertEquals(expected, json.toString());
    }
}
