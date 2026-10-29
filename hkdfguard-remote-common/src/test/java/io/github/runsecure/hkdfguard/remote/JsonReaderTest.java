package io.github.runsecure.hkdfguard.remote;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** JsonReader accepts exactly RFC 8259 JSON, as strictly as .NET's Utf8JsonReader. */
class JsonReaderTest {
    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static List<Token> tokens(String json) {
        var bytes = utf8(json);
        var reader = new JsonReader(bytes, bytes.length);
        var tokens = new ArrayList<Token>();
        while (reader.read())
            tokens.add(reader.token());
        return tokens;
    }

    @Test
    void everyKindOfToken_IsRead() {
        assertEquals(List.of(Token.START_OBJECT, Token.PROPERTY_NAME, Token.START_ARRAY, Token.STRING, Token.NUMBER, Token.TRUE,
                Token.FALSE, Token.NULL, Token.START_OBJECT, Token.END_OBJECT, Token.START_ARRAY, Token.END_ARRAY, Token.END_ARRAY,
                Token.END_OBJECT), tokens(" {\"a\" : [ \"s\", -0.5e+10, true, false, null, {}, [] ] }\r\n\t"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "-0", "12", "1.25", "1e5", "1E-5", "-12.5e+3", "\"text\"", "true", "null", "[]", "{}"})
    void anyValue_CanBeTheRoot(String json) {
        assertEquals(1 + (json.startsWith("[") || json.startsWith("{") ? 1 : 0), tokens(json).size());
    }

    @Test
    void emptyOrWhitespaceInput_HasNoTokens() {
        assertTrue(tokens("").isEmpty());
        assertTrue(tokens(" \n ").isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "01", "-", "1.", "1.e5", "1e", "1e+", ".5", "+1", "1x", "tru", "trUe", "nul", "falsy",
            "{", "[", "{\"a\"", "{\"a\":", "{\"a\" 1}", "{\"a\":1,}", "[1,]", "[1 2]", "{\"a\":1 \"b\":2}", "{1:2}", "{,}", "[,1]",
            "\"unterminated", "\"bad \\x escape\"", "\"\\u12\"", "\"\\u12G4\"", "\"\\udc00\"", "\"\\ud800\"", "\"\\ud800\\u0041\"",
            "\"\\ud800x\"", "\"tab\there\"", "1 2", "{} {}", "]", "}", "/* comment */ 1", "{\"a\":1}/",
    })
    void malformedJson_IsRefused(String json) {
        assertThrows(JsonReader.Malformed.class, () -> tokens(json));
    }

    @Test
    void nestingDeeperThanTheLimit_IsRefused_AndToItIsNot() {
        var atLimit = "[".repeat(JsonReader.MAX_DEPTH) + "]".repeat(JsonReader.MAX_DEPTH);
        assertEquals(2 * JsonReader.MAX_DEPTH, tokens(atLimit).size());

        var beyond = "[".repeat(JsonReader.MAX_DEPTH + 1) + "]".repeat(JsonReader.MAX_DEPTH + 1);
        assertThrows(JsonReader.Malformed.class, () -> tokens(beyond));
    }

    @Test
    void anError_IsPlacedByLineAndPositionInIt() {
        var e = assertThrows(JsonReader.Malformed.class, () -> tokens("{\n\"a\":\n  x}"));

        assertEquals(2, e.line);
        assertEquals(2, e.position);
        assertFalse(e.getMessage().contains("x"));
    }

    @Test
    void skip_PassesOverAContainersChildren_AndNothingElse() {
        var bytes = utf8("{\"a\":{\"b\":[1,{\"c\":2}]},\"d\":3}");
        var reader = new JsonReader(bytes, bytes.length);
        reader.read();
        reader.read();
        reader.read();
        assertEquals(Token.START_OBJECT, reader.token());

        reader.skip();
        assertEquals(Token.END_OBJECT, reader.token());
        reader.read();
        assertEquals("d", reader.getString());
        reader.read();
        reader.skip();
        assertEquals(Token.NUMBER, reader.token());
    }

    @Test
    void copyString_Unescapes_AndValueTextEqualsComparesTheUnescapedText() {
        var bytes = utf8("{\"k\\u0065y\":\"\\u00e9\\u4e2d\\ud83d\\ude00\\\"\"}");
        var reader = new JsonReader(bytes, bytes.length);
        reader.read();
        reader.read();
        assertTrue(reader.valueTextEquals("key"));
        assertFalse(reader.valueTextEquals("kex"));
        assertEquals("key", reader.getString());

        reader.read();
        var destination = new byte[reader.valueLength()];
        var length = reader.copyString(destination);
        assertEquals("é中\uD83D\uDE00\"", new String(destination, 0, length, java.nio.charset.StandardCharsets.UTF_8));
    }

    @Test
    void theTokenBounds_CoverAStringsQuotes() {
        var bytes = utf8("{\"a\": \"xyz\"}");
        var reader = new JsonReader(bytes, bytes.length);
        reader.read();
        reader.read();
        reader.read();

        assertEquals(6, reader.tokenStart());
        assertEquals(11, reader.bytesConsumed());
        assertEquals(3, reader.valueLength());
    }

    @Test
    void getString_ReplacesInvalidUtf8() {
        var bytes = new byte[] {'"', (byte) 0xFF, '"'};
        var reader = new JsonReader(bytes, bytes.length);
        reader.read();

        assertEquals("\uFFFD", reader.getString());
    }
}
