package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class WrappedDekEnvelopeTest {
    private static final String WRAP_VERSION = "0123456789abcdef0123456789abcdef";
    private static final String SIGN_VERSION = "fedcba9876543210fedcba9876543210";

    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] random(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static byte[] envelope(int wrappedLength) {
        var unsigned = WrappedDekEnvelope.buildUnsigned(WRAP_VERSION, random(wrappedLength));
        var envelope = new byte[unsigned.length + WrappedDekEnvelope.KEY_VERSION_LENGTH + WrappedDekEnvelope.SIGNATURE_LENGTH];
        assertEquals(envelope.length, WrappedDekEnvelope.write(unsigned, SIGN_VERSION, random(64), envelope));
        return envelope;
    }

    @Test
    void writeThenParse_RoundTripsEveryPart() {
        var wrapped = random(256);
        var signature = random(64);
        var unsigned = WrappedDekEnvelope.buildUnsigned(WRAP_VERSION.toUpperCase(Locale.ROOT), wrapped);
        var envelope = new byte[512];
        int length = WrappedDekEnvelope.write(unsigned, SIGN_VERSION, signature, envelope);

        var parts = WrappedDekEnvelope.parse(Arrays.copyOf(envelope, length));

        assertEquals(256 + WrappedDekEnvelope.OVERHEAD, length);
        assertEquals(WRAP_VERSION, parts.wrappingKeyVersion());
        assertArrayEquals(wrapped, parts.wrappedDek());
        assertEquals(SIGN_VERSION, parts.signingKeyVersion());
        assertArrayEquals(signature, parts.signature());
        assertEquals(unsigned.length, parts.unsignedLength());
        assertArrayEquals("HGKV".getBytes(StandardCharsets.US_ASCII), Arrays.copyOf(envelope, 4));
    }

    @Test
    void theLayout_IsTheDotNetWrappersByteForByte() {
        // The format AzureKeyVaultKeyWrapper (.NET) writes and reads; a key file made by either
        // must be read by the other.
        var unsigned = WrappedDekEnvelope.buildUnsigned(WRAP_VERSION, new byte[] {(byte) 0xC1, (byte) 0xC2, (byte) 0xC3});
        var envelope = new byte[unsigned.length + 80];
        WrappedDekEnvelope.write(unsigned, SIGN_VERSION, filled(64, 0x5A), envelope);

        var hex = HexFormat.of();
        assertEquals("48474b56" + "01" + WRAP_VERSION + "0003" + "c1c2c3" + SIGN_VERSION + "5a".repeat(64), hex.formatHex(envelope));
        assertEquals(hex.formatHex("HkdfGuard-AzureKeyVault-wrap-v1\0".getBytes(StandardCharsets.US_ASCII)) + "0005" + hex.formatHex("myapp".getBytes(StandardCharsets.UTF_8))
                + hex.formatHex(unsigned),
                hex.formatHex(WrappedDekEnvelope.signedData(envelope, unsigned.length, WrappedDekEnvelope.encodeContext("myapp"))));
    }

    @Test
    void parse_RefusesWhatIsNotAnEnvelope() {
        assertThrows(CryptographicException.class, () -> WrappedDekEnvelope.parse(new byte[WrappedDekEnvelope.OVERHEAD]));
        assertThrows(CryptographicException.class, () -> WrappedDekEnvelope.parse(random(300)));
        assertThrows(CryptographicException.class, () -> WrappedDekEnvelope.parse(new byte[0]));
    }

    @Test
    void parse_RefusesAnotherFormatVersion() {
        var envelope = envelope(256);
        envelope[4] = 2;

        var exception = assertThrows(CryptographicException.class, () -> WrappedDekEnvelope.parse(envelope));

        assertTrue(exception.getMessage().contains("format version 2"));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 1})
    void parse_RefusesALengthThatDisagreesWithTheHeader(int delta) {
        var envelope = envelope(256);

        assertThrows(CryptographicException.class, () -> WrappedDekEnvelope.parse(Arrays.copyOf(envelope, envelope.length + delta)));
    }

    @Test
    void parse_ReadsTheCiphertextLengthAsUnsigned() {
        // 0x80 in the high byte: a signed read would make the length negative.
        var envelope = envelope(256);
        envelope[21] = (byte) 0x80;
        envelope[22] = 0;

        var exception = assertThrows(CryptographicException.class, () -> WrappedDekEnvelope.parse(envelope));

        assertTrue(exception.getMessage().contains("describes " + (WrappedDekEnvelope.OVERHEAD + 0x8000)), exception.getMessage());
    }

    @Test
    void parse_RefusesAnEmptyCiphertext() {
        var envelope = envelope(1);
        envelope[21] = 0;
        envelope[22] = 0;

        assertThrows(CryptographicException.class, () -> WrappedDekEnvelope.parse(envelope));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 65_536})
    void buildUnsigned_RefusesACiphertextItCanNotEncode(int length) {
        assertThrows(CryptographicException.class, () -> WrappedDekEnvelope.buildUnsigned(WRAP_VERSION, new byte[length]));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "0123456789abcdef0123456789abcde",   // 31 digits
        "0123456789abcdef0123456789abcdef0", // 33
        "0123456789abcdef0123456789abcdeg",  // not hex
        "0123456789abcdef0123456789abcd٣٤" // Arabic-Indic digits: digits, but not hex
    })
    void buildUnsignedAndWrite_RefuseAVersionThatIsNotKeyVaults(String version) {
        assertThrows(CryptographicException.class, () -> WrappedDekEnvelope.buildUnsigned(version, new byte[256]));

        var unsigned = WrappedDekEnvelope.buildUnsigned(WRAP_VERSION, new byte[256]);
        var result = new byte[512];
        assertThrows(CryptographicException.class, () -> WrappedDekEnvelope.write(unsigned, version, new byte[64], result));
        assertTrue(Arrays.equals(new byte[512], result), "A refused version leaves result as it was.");
    }

    @ParameterizedTest
    @ValueSource(ints = {63, 72})
    void write_RefusesASignatureThatIsNotEs256(int length) {
        var unsigned = WrappedDekEnvelope.buildUnsigned(WRAP_VERSION, new byte[256]);

        var exception = assertThrows(CryptographicException.class, () -> WrappedDekEnvelope.write(unsigned, SIGN_VERSION, new byte[length], new byte[512]));

        assertTrue(exception.getMessage().contains("EC P-256"));
    }

    @Test
    void write_RefusesAResultTooSmall() {
        var unsigned = WrappedDekEnvelope.buildUnsigned(WRAP_VERSION, new byte[256]);

        assertThrows(IllegalArgumentException.class, () -> WrappedDekEnvelope.write(unsigned, SIGN_VERSION, new byte[64], new byte[unsigned.length + 79]));
    }

    @Test
    void signedData_BindsTheDomainContextAndEnvelope() {
        var unsigned = WrappedDekEnvelope.buildUnsigned(WRAP_VERSION, new byte[256]);

        var none = WrappedDekEnvelope.signedData(unsigned, unsigned.length, WrappedDekEnvelope.encodeContext(null));
        var empty = WrappedDekEnvelope.signedData(unsigned, unsigned.length, WrappedDekEnvelope.encodeContext(""));
        var app = WrappedDekEnvelope.signedData(unsigned, unsigned.length, WrappedDekEnvelope.encodeContext("com.example.myapp"));

        assertArrayEquals(none, empty);
        assertFalse(Arrays.equals(none, app));
        var domain = "HkdfGuard-AzureKeyVault-wrap-v1\0".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(domain, Arrays.copyOf(app, domain.length));
        assertArrayEquals(unsigned, Arrays.copyOfRange(app, app.length - unsigned.length, app.length));
    }

    @Test
    void encodeContext_RefusesOneTooLongToLengthPrefix() {
        assertThrows(IllegalArgumentException.class, () -> WrappedDekEnvelope.encodeContext("x".repeat(65_536)));
        // Counted in UTF-8 bytes, not characters: 21,846 three-byte characters are 65,538 bytes.
        assertThrows(IllegalArgumentException.class, () -> WrappedDekEnvelope.encodeContext("€".repeat(21_846)));
        assertEquals(65_535, WrappedDekEnvelope.encodeContext("x".repeat(65_535)).length);
    }

    @Test
    void encodeContext_IsUtf8() {
        assertArrayEquals(new byte[] {'a', (byte) 0xE2, (byte) 0x82, (byte) 0xAC, (byte) 0xF0, (byte) 0x9F, (byte) 0x94, (byte) 0x91},
                WrappedDekEnvelope.encodeContext("a€🔑"));
    }

    private static byte[] filled(int length, int value) {
        var bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
