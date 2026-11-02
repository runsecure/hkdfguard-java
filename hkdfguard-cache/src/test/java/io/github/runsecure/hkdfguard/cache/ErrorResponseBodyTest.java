package io.github.runsecure.hkdfguard.cache;

import static io.github.runsecure.hkdfguard.cache.TestRings.utf8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** ErrorResponseBody reads a store's error messages, and nothing it can't trust as JSON. */
class ErrorResponseBodyTest {
    private static List<String> read(String body) throws IOException {
        return ErrorResponseBody.readStrings(new ByteArrayInputStream(utf8(body)), "errors");
    }

    @Test
    void theArraysElements_AreReturned_StringsAsTheirTextAndAnythingElseAsJson() throws IOException {
        assertEquals(List.of("permission denied", "a \"quoted\" é", "42", "{\"a\":[1]}", "null"),
                read("{\"warnings\":[\"w\"],\"errors\":[\"permission denied\",\"a \\\"quoted\\\" \\u00e9\",42,{\"a\":[1]},null],\"n\":{}}"));
    }

    @Test
    void anObjectWithoutTheProperty_HasNoErrors() throws IOException {
        assertEquals(List.of(), read("{\"data\":{\"k\":\"v\"}}"));
        assertEquals(List.of(), read("{\"errors\":[]}"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "<html>Bad Gateway</html>", "[\"errors\"]", "{\"errors\":\"denied\"}", "{\"errors\":[\"x\"]} trailing", "{\"errors\":[\"x\""})
    void aBodyThatIsntAnObjectWithAnArray_IsNull(String body) throws IOException {
        assertNull(read(body));
    }

    @Test
    void aBodyBeyondTheLimit_IsReadOnlyThatFar_AndIsntJson() throws IOException {
        var body = "{\"errors\":[\"" + "x".repeat(ErrorResponseBody.MAX_BODY_LENGTH) + "\"]}";

        assertNull(read(body));
    }

    @Test
    void aReadFailure_Propagates() {
        var failing = new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("reset");
            }
        };

        assertThrows(IOException.class, () -> ErrorResponseBody.readStrings(failing, "errors"));
        assertThrows(NullPointerException.class, () -> ErrorResponseBody.readStrings(null, "errors"));
        assertThrows(NullPointerException.class, () -> ErrorResponseBody.readStrings(new ByteArrayInputStream(new byte[0]), null));
    }
}
