package io.github.runsecure.hkdfguard.cache;

import static io.github.runsecure.hkdfguard.cache.TestRings.utf8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** SecretJsonBody hands a JSON body's secret to a sink and returns the body with it blanked. */
class SecretJsonBodyTest {
    private final KeyRingImpl ring = TestRings.ring();

    @AfterEach
    void closeRing() {
        ring.close();
    }

    private FakeRemoteSecretCache createCache() {
        return new FakeRemoteSecretCache(ring, SecretNameMatching.EXACT);
    }

    private static InputStream stream(String body) {
        return new ByteArrayInputStream(utf8(body));
    }

    private record Captured(String redacted, byte[] cached) {
    }

    // Runs capture inside a fetch, as a provider's pipeline does; returns the redacted body and the value cached.
    private Captured capture(String body, String text, String base64) {
        var cache = createCache();
        var redacted = new String[1];
        cache.onFetch = (name, sink) -> redacted[0] = new String(SecretJsonBody.capture(stream(body), sink, text, base64), StandardCharsets.UTF_8);

        var result = new byte[body.length() + 16];
        var written = cache.decrypt("item", result);
        return new Captured(redacted[0], Arrays.copyOf(result, written));
    }

    private Captured capture(String body) {
        return capture(body, "value", null);
    }

    private byte[] decryptBytes(FakeRemoteSecretCache cache, String name) {
        var result = new byte[256];
        return Arrays.copyOf(result, cache.decrypt(name, result));
    }

    @Test
    void theTextValue_IsHandedOver_AndBlankedInTheBody() {
        var captured = capture("{\"id\":\"x\",\"value\":\"s3cret\",\"n\":1}");

        assertArrayEquals(utf8("s3cret"), captured.cached());
        assertEquals("{\"id\":\"x\",\"value\":\"\",\"n\":1}", captured.redacted());
    }

    @Test
    void theBase64Value_IsHandedOverDecoded() {
        var captured = capture("{\"SecretString\":null,\"SecretBinary\":\"AAH+/w==\"}", "SecretString", "SecretBinary");

        assertArrayEquals(new byte[] {0, 1, (byte) 254, (byte) 255}, captured.cached());
        assertEquals("{\"SecretString\":null,\"SecretBinary\":\"\"}", captured.redacted());
    }

    @Test
    void escapesAreUnescaped() {
        var captured = capture("{\"value\":\"a\\\"b\\\\c\\u00e9\\n\\/\\b\\f\\r\\t\\ud83d\\ude00é\"}");

        assertEquals("a\"b\\cé\n/\b\f\r\t😀é", new String(captured.cached(), StandardCharsets.UTF_8));
    }

    @Test
    void aNestedPropertyOfTheSameName_IsLeftAlone() {
        var captured = capture("{\"tags\":{\"value\":\"tag\"},\"list\":[{\"value\":\"x\"}],\"value\":\"top\"}");

        assertArrayEquals(utf8("top"), captured.cached());
        assertEquals("{\"tags\":{\"value\":\"tag\"},\"list\":[{\"value\":\"x\"}],\"value\":\"\"}", captured.redacted());
    }

    @Test
    void anEscapedPropertyName_IsMatchedUnescaped() {
        var captured = capture("{\"val\\u0075e\":\"s3cret\"}");

        assertArrayEquals(utf8("s3cret"), captured.cached());
        assertEquals("{\"val\\u0075e\":\"\"}", captured.redacted());
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"other\":\"x\"}", "{\"value\":null}", "{\"value\":42}", "{\"value\":\"\"}", "{}"})
    void noNonEmptyStringValue_HandsNothingOver(String body) {
        var captured = capture(body);

        assertEquals(0, captured.cached().length);
        assertEquals(body, captured.redacted());
    }

    @Test
    void emptyDuplicates_AreBlankedAlongsideTheValue() {
        var captured = capture("{\"value\":\"\",\"value\":\"s\",\"value\":\"\"}");

        assertArrayEquals(utf8("s"), captured.cached());
        assertEquals("{\"value\":\"\",\"value\":\"\",\"value\":\"\"}", captured.redacted());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', nullValues = "-", value = {
            "{\"value\":\"a\",\"value\":\"b\"}|value|-",
            "{\"SecretString\":\"a\",\"SecretBinary\":\"Yg==\"}|SecretString|SecretBinary",
            "{\"SecretBinary\":\"not base64!\"}|SecretString|SecretBinary",
            "[\"value\"]|value|-",
            "{\"value\":\"unterminated|value|-",
            "\"value\"|value|-",
    })
    void aBodyThatCantBeTrusted_IsRefused_AndNothingIsCached(String body, String text, String base64) {
        var cache = createCache();
        cache.onFetch = (name, sink) -> SecretJsonBody.capture(stream(body), sink, text, base64);

        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));

        cache.onFetch = null;
        assertEquals(0, cache.decrypt("item", new byte[16]));
    }

    @Test
    void anEmptyBody_IsRefused() {
        var cache = createCache();
        cache.onFetch = (name, sink) -> SecretJsonBody.capture(stream(""), sink, "value");

        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {"{\"value\":\"s3cr\\qt\"}|15", "{\"value\":\"s3cr\u0001t\"}|14"})
    void aMalformedSecret_IsReportedByPositionOnly_NeverByTheByteRejected(String body, long position) {
        var cache = createCache();
        cache.onFetch = (name, sink) -> SecretJsonBody.capture(stream(body), sink, "value");

        var e = assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));

        assertEquals("The response body isn't valid JSON (at byte " + position + " of line 0).", e.getMessage());
        assertNull(e.getCause());
    }

    @Test
    void aMalformedSecret_IsReportedByItsPositionInItsOwnLine() {
        var cache = createCache();
        cache.onFetch = (name, sink) -> SecretJsonBody.capture(stream("{\n  \"value\":\"s3cr\\qt\"}"), sink, "value");

        var e = assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));

        assertEquals("The response body isn't valid JSON (at byte 16 of line 1).", e.getMessage());
    }

    @Test
    void aBodyLargerThanTheFirstBuffer_IsReadWhole() {
        var padding = "x".repeat(100_000);
        var captured = capture("{\"pad\":\"" + padding + "\",\"value\":\"s3cret\"}");

        assertArrayEquals(utf8("s3cret"), captured.cached());
        assertEquals("{\"pad\":\"" + padding + "\",\"value\":\"\"}", captured.redacted());
    }

    @Test
    void aBodyAtTheLimit_IsRefused() {
        var cache = createCache();
        cache.onFetch = (name, sink) -> SecretJsonBody.capture(new ByteArrayInputStream(new byte[SecretJsonBody.MAX_BODY_LENGTH]), sink, "value");

        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));
    }

    @Test
    void aBodyThatCantBeRead_FailsWithTheReadError() {
        var cache = createCache();
        var failing = new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("connection reset");
            }
        };
        cache.onFetch = (name, sink) -> SecretJsonBody.capture(failing, sink, "value");

        var e = assertThrows(UncheckedIOException.class, () -> cache.decrypt("item", new byte[16]));
        assertEquals("connection reset", e.getCause().getMessage());
    }

    @Test
    void aNestedValue_IsHandedOver_AndOnlyItIsBlanked() {
        var cache = createCache();
        var redacted = new String[1];
        var body = "{\"value\":\"top\",\"data\":{\"value\":\"middle\",\"data\":{\"other\":1,\"value\":\"s3cret\"},\"metadata\":{\"value\":\"m\"}}}";
        cache.onFetch = (name, sink) -> redacted[0] = new String(
                SecretJsonBody.capture(stream(body), sink, List.of("data", "data"), "value", null), StandardCharsets.UTF_8);

        assertArrayEquals(utf8("s3cret"), decryptBytes(cache, "item"));
        assertEquals("{\"value\":\"top\",\"data\":{\"value\":\"middle\",\"data\":{\"other\":1,\"value\":\"\"},\"metadata\":{\"value\":\"m\"}}}", redacted[0]);
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"data\":null}", "{\"data\":\"value\"}", "{\"data\":[{\"value\":\"x\"}]}", "{\"other\":{\"value\":\"x\"}}"})
    void aPathLeadingToNoObject_HandsNothingOver(String body) {
        var cache = createCache();
        cache.onFetch = (name, sink) -> SecretJsonBody.capture(stream(body), sink, List.of("data"), "value", null);

        assertEquals(0, cache.decrypt("item", new byte[16]));
    }

    @Test
    void valuesUnderDuplicateParents_AreRefused() {
        var cache = createCache();
        cache.onFetch = (name, sink) -> SecretJsonBody.capture(
                stream("{\"data\":{\"value\":\"a\"},\"data\":{\"value\":\"b\"}}"), sink, List.of("data"), "value", null);

        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));
    }

    @Test
    void aTextValueHoldingAJsonObject_IsHandedOverWholeAndByKey_ButABase64OneIsNot() {
        var cache = createCache();
        var json = "{\"user\":\"app\",\"pass\":\"s3cret\"}";
        var body = "{\"SecretString\":\"" + json.replace("\"", "\\\"") + "\"}";
        cache.onFetch = (name, sink) -> SecretJsonBody.capture(stream(body), sink, "SecretString", "SecretBinary");

        assertArrayEquals(utf8("s3cret"), decryptBytes(cache, "item#pass"));
        assertArrayEquals(utf8("app"), decryptBytes(cache, "item#user"));
        assertArrayEquals(utf8(json), decryptBytes(cache, "item"));

        var binary = "{\"SecretBinary\":\"" + Base64.getEncoder().encodeToString(utf8(json)) + "\"}";
        cache.onFetch = (name, sink) -> SecretJsonBody.capture(stream(binary), sink, "SecretString", "SecretBinary");
        assertArrayEquals(utf8(json), decryptBytes(cache, "binary"));
        assertEquals(0, cache.decrypt("binary#pass", new byte[16]));
    }

    @Test
    void captureKeys_HandsOverEveryMemberOfTheObjectAtThePath() {
        var cache = createCache();
        var body = "{\"data\":{\"data\":{\"username\":\"app\",\"password\":\"s3cret\",\"port\":5432},\"metadata\":{\"version\":3}},\"value\":\"top\"}";
        cache.onFetch = (name, sink) -> SecretJsonBody.captureKeys(stream(body), sink, List.of("data", "data"));

        assertArrayEquals(utf8("s3cret"), decryptBytes(cache, "item#password"));
        assertArrayEquals(utf8("app"), decryptBytes(cache, "item#username"));
        assertArrayEquals(utf8("5432"), decryptBytes(cache, "item#port"));
        assertEquals(0, cache.decrypt("item", new byte[16]));
        assertEquals(0, cache.decrypt("item#version", new byte[16]));
        assertEquals(0, cache.decrypt("item#value", new byte[16]));
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"data\":{\"data\":null}}", "{\"data\":{\"other\":{\"k\":\"v\"}}}", "{\"data\":{\"data\":{}}}"})
    void captureKeys_WithNoKeysAtThePath_HandsNothingOver(String body) {
        var cache = createCache();
        cache.onFetch = (name, sink) -> SecretJsonBody.captureKeys(stream(body), sink, List.of("data", "data"));

        assertEquals(0, cache.decrypt("item#k", new byte[16]));
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"data\":{\"k\":\"a\"},\"data\":{\"k\":\"b\"}}", "{\"data\":{\"k\":\"a\",\"k\":\"b\"}}", "{\"data\":{\"k\":\"a\",}}", "[\"data\"]"})
    void captureKeys_RefusesABodyThatCantBeTrusted_AndCachesNothing(String body) {
        var cache = createCache();
        cache.onFetch = (name, sink) -> SecretJsonBody.captureKeys(stream(body), sink, List.of("data"));

        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item#k", new byte[16]));
    }

    @Test
    void theArguments_AreChecked() {
        var cache = createCache();
        cache.onFetch = (name, sink) -> {
            assertThrows(NullPointerException.class, () -> SecretJsonBody.capture(null, sink, "value"));
            assertThrows(NullPointerException.class, () -> SecretJsonBody.capture(stream("{}"), null, "value"));
            assertThrows(IllegalArgumentException.class, () -> SecretJsonBody.capture(stream("{}"), sink, ""));
            assertThrows(IllegalArgumentException.class, () -> SecretJsonBody.capture(stream("{}"), sink, null));
            assertThrows(IllegalArgumentException.class, () -> SecretJsonBody.capture(stream("{}"), sink, List.of("data", ""), "value", null));
            assertThrows(IllegalArgumentException.class, () -> SecretJsonBody.capture(stream("{}"), sink, Arrays.asList((String) null), "value", null));
            assertThrows(NullPointerException.class, () -> SecretJsonBody.capture(stream("{}"), sink, null, "value", null));
            assertThrows(NullPointerException.class, () -> SecretJsonBody.captureKeys(null, sink, List.of("data")));
            assertThrows(NullPointerException.class, () -> SecretJsonBody.captureKeys(stream("{}"), null, List.of("data")));
            assertThrows(IllegalArgumentException.class, () -> SecretJsonBody.captureKeys(stream("{}"), sink, List.of("")));
        };

        assertEquals(0, cache.decrypt("item", new byte[16]));
    }
}
