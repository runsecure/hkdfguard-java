package io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DefaultFormatProviderImplTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final DefaultFormatProviderImpl provider = new DefaultFormatProviderImpl();

    private static byte[] random(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    @Test
    void formatParseAndGetMaxDecryptedLength_WithSensitiveLoggingEnabled_StillWork() {
        var original = HkdfGuardTelemetry.DATA_PROTECTION.isSensitiveLoggingEnabled();
        HkdfGuardTelemetry.DATA_PROTECTION.setSensitiveLoggingEnabled(true);
        try {
            var value = new KeyTrackingValue(2, "abc".getBytes(StandardCharsets.UTF_8));
            var formatted = provider.format(value);

            assertArrayEquals(value.value(), provider.parse(formatted).value());
            assertEquals(3, provider.getMaxDecryptedLength(formatted));
        } finally {
            HkdfGuardTelemetry.DATA_PROTECTION.setSensitiveLoggingEnabled(original);
        }
    }

    @Test
    void formatThenParse_RoundTrips() {
        var value = new KeyTrackingValue(7, "hello".getBytes(StandardCharsets.UTF_8));

        var formatted = provider.format(value);
        assertTrue(formatted.startsWith("enc::v7::"));

        var parsed = provider.parse(formatted);
        assertEquals(7, parsed.keyVersion());
        assertArrayEquals(value.value(), parsed.value());
    }

    @Test
    void theWireFormat_MatchesEveryOtherPort() {
        assertEquals("enc::v1::AQID", provider.format(new KeyTrackingValue(1, new byte[] {1, 2, 3})));
    }

    @Test
    void format_WithAnEmptyValue_RoundTrips() {
        var parsed = provider.parse(provider.format(new KeyTrackingValue(1, new byte[0])));

        assertEquals(1, parsed.keyVersion());
        assertEquals(0, parsed.value().length);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "no-delimiters-at-all", "enc::onlyonepart", "wrong::v1::AAAA", "enc::1::AAAA", "enc::vNotANumber::AAAA"})
    void parse_WithMalformedInput_Throws(String input) {
        assertThrows(EncryptedFormatException.class, () -> provider.parse(input));
    }

    @Test
    void parse_WithInvalidBase64_Throws() {
        assertThrows(EncryptedFormatException.class, () -> provider.parse("enc::v1::not-valid-base64!!!"));
    }

    @Test
    void getMaxDecryptedLength_MatchesTheParsedValueLength() {
        var formatted = provider.format(new KeyTrackingValue(3, random(40)));

        assertEquals(provider.parse(formatted).value().length, provider.getMaxDecryptedLength(formatted));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "enc::onlyonepart", "enc::1::AAAA", "enc::v1::not-valid-base64!!!"})
    void getMaxDecryptedLength_WithMalformedInput_Throws(String input) {
        assertThrows(EncryptedFormatException.class, () -> provider.getMaxDecryptedLength(input));
    }

    @Test
    void formatAndParse_ANegativeVersion_RoundTripUnderAnyLocale() {
        var original = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("ar-EG"));
        try {
            var formatted = provider.format(new KeyTrackingValue(-5, new byte[] {1, 2, 3}));

            assertTrue(formatted.startsWith("enc::v-5::"));
            assertEquals(-5, provider.parse(formatted).keyVersion());
        } finally {
            Locale.setDefault(original);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"enc::v+1::AQID", "enc::v 1::AQID", "enc::v1 ::AQID", "enc::v~1::AQID", "enc::v::AQID", "enc::v-::AQID",
            "enc::v١::AQID", "enc::v99999999999::AQID"})
    void parse_RejectsVersionsThatAreNotInCanonicalForm(String encrypted) {
        assertThrows(EncryptedFormatException.class, () -> provider.parse(encrypted));
    }

    @ParameterizedTest
    @ValueSource(strings = {"enc::v1::AQID    ", "enc::v1::AQ ID", "enc::v1::AQID\t", "enc::v1::AQID\r\n", "enc::v1:: AQID"})
    void parseAndGetMaxDecryptedLength_RejectBase64ContainingWhitespace(String encrypted) {
        assertThrows(EncryptedFormatException.class, () -> provider.parse(encrypted));
        assertThrows(EncryptedFormatException.class, () -> provider.getMaxDecryptedLength(encrypted));
    }

    @Test
    void format_WithANullValue_Throws() {
        assertThrows(NullPointerException.class, () -> provider.format(null));
    }

    // "enc::v1234::" is 12 characters, leaving exactly 4084 for base64 - which encodes 3063 bytes.
    private static KeyTrackingValue valueFormattingTo(int extraBytes) {
        return new KeyTrackingValue(1234, random(3063 + extraBytes));
    }

    @Test
    void maxEncryptedLength_DefaultsTo4096() {
        assertEquals(4096, DefaultFormatProviderImpl.DEFAULT_MAX_ENCRYPTED_LENGTH);
        assertEquals(4096, new DefaultFormatProviderImpl().getMaxEncryptedLength());
    }

    @Test
    void formatAndParse_AValueOfExactlyTheLimit_RoundTrips() {
        var value = valueFormattingTo(0);

        var formatted = provider.format(value);

        assertEquals(4096, formatted.length());
        assertArrayEquals(value.value(), provider.parse(formatted).value());
        assertEquals(3063, provider.getMaxDecryptedLength(formatted));
    }

    @Test
    void format_AValueOverTheLimit_IsRefusedRatherThanWrittenUnreadable() {
        var exception = assertThrows(IllegalArgumentException.class, () -> provider.format(valueFormattingTo(1)));

        assertTrue(exception.getMessage().contains("4096"));
    }

    @Test
    void parseAndGetMaxDecryptedLength_InputOverTheLimit_AreRejectedBeforeDecoding() {
        var tooLong = "enc::v1234::" + "A".repeat(4088);

        assertThrows(EncryptedFormatException.class, () -> provider.parse(tooLong));
        assertThrows(EncryptedFormatException.class, () -> provider.getMaxDecryptedLength(tooLong));
    }

    @Test
    void aCustomLimit_AppliesToFormatAndParse() {
        var small = new DefaultFormatProviderImpl(64);
        var tooBig = new KeyTrackingValue(1, new byte[40]); // 9 + 56 = 65 > 64
        var fits = new KeyTrackingValue(1, new byte[39]);   // 9 + 52 = 61

        assertThrows(IllegalArgumentException.class, () -> small.format(tooBig));
        assertEquals(39, small.parse(small.format(fits)).value().length);
        assertThrows(EncryptedFormatException.class, () -> small.parse(provider.format(tooBig)));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void constructor_WithANonPositiveLimit_Throws(int maxEncryptedLength) {
        assertThrows(IllegalArgumentException.class, () -> new DefaultFormatProviderImpl(maxEncryptedLength));
    }
}
