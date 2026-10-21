package io.github.runsecure.hkdfguard.abstractions;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class Utf8UtilityTest {
    @ParameterizedTest
    @ValueSource(strings = {"", "hello", "héllo wörld ✓ 🔐", "秘密", "\u007F\u0080߿ࠀ￿"})
    void encode_WellFormedText_MatchesTheJdksUtf8(String text) {
        var expected = text.getBytes(StandardCharsets.UTF_8);

        assertArrayEquals(expected, Utf8Utility.encode(text));
        assertArrayEquals(expected, Utf8Utility.encodeStrict(text));
        assertEquals(expected.length, Utf8Utility.encodedLength(text));
    }

    @Test
    void encode_AnUnpairedSurrogate_BecomesUFFFD_AsInDotNet() {
        // Java's own encoder would write '?' (0x3F); .NET writes EF BF BD, and every port must agree.
        assertArrayEquals(new byte[] {'a', (byte) 0xEF, (byte) 0xBF, (byte) 0xBD, 'b'}, Utf8Utility.encode("a\uD800b"));
        assertArrayEquals(new byte[] {(byte) 0xEF, (byte) 0xBF, (byte) 0xBD}, Utf8Utility.encode("\uDC00"));
        assertEquals(3, Utf8Utility.encodedLength("\uD800"));
    }

    @Test
    void encodeStrict_AnUnpairedSurrogate_Throws() {
        assertThrows(IllegalArgumentException.class, () -> Utf8Utility.encodeStrict("Key\uD800Tail"));
        assertThrows(IllegalArgumentException.class, () -> Utf8Utility.encodeStrict("Key\uDC00Tail"));
        assertThrows(IllegalArgumentException.class, () -> Utf8Utility.requireWellFormed("Key\uD800"));
    }

    @Test
    void decode_RoundTripsAndReportsTheCharCount() {
        var bytes = "héllo 🔐".getBytes(StandardCharsets.UTF_8);
        var result = new char[16];

        var written = Utf8Utility.decode(bytes, bytes.length, result);

        assertEquals("héllo 🔐", new String(result, 0, written));
    }

    @Test
    void decode_OnlyThePrefixGiven() {
        var bytes = "hello world".getBytes(StandardCharsets.UTF_8);
        var result = new char[16];

        assertEquals("hello", new String(result, 0, Utf8Utility.decode(bytes, 5, result)));
    }

    @Test
    void decode_IntoATooSmallDestination_Throws() {
        var bytes = "hello".getBytes(StandardCharsets.UTF_8);

        assertThrows(IllegalArgumentException.class, () -> Utf8Utility.decode(bytes, bytes.length, new char[4]));
    }

    @Test
    void decode_IntoATooSmallDestination_ThrowsAndLeavesNoPlaintextBehind() {
        // The decoder fills the destination before it overflows; none of that may survive the throw.
        var bytes = "top secret".getBytes(StandardCharsets.UTF_8);
        var result = new char[5];

        assertThrows(IllegalArgumentException.class, () -> Utf8Utility.decode(bytes, bytes.length, result));
        assertArrayEquals(new char[5], result);
    }

    @Test
    void decode_MalformedInput_BecomesUFFFD() {
        var result = new char[4];

        var written = Utf8Utility.decode(new byte[] {'a', (byte) 0xFF, 'b'}, 3, result);

        assertEquals("a�b", new String(result, 0, written));
    }
}
