package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import java.nio.CharBuffer;
import java.nio.ReadOnlyBufferException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AesGcmPipelineDataProtectorImplTest {
    private static final String ID = "Pipeline:Secret";
    private static final int VERSION = 3;

    private static AesGcmPipelineDataProtectorImpl create() {
        return create(VERSION);
    }

    private static AesGcmPipelineDataProtectorImpl create(int version) {
        return new AesGcmPipelineDataProtectorImpl(new TestFormatProvider(), version);
    }

    private static String decrypt(PipelineDataProtector protector, String formatted, String secretIdentifier) {
        var result = new char[protector.getMaxDecryptedLength(formatted)];
        var written = protector.decrypt(formatted, secretIdentifier, result);
        return new String(result, 0, written);
    }

    @ParameterizedTest
    @ValueSource(strings = {"hello", "héllo wörld ✓ 🔐", ""})
    void encryptDecrypt_RoundTrips(String plaintext) {
        try (var protector = create()) {
            var formatted = protector.encrypt(plaintext, ID);

            assertEquals(plaintext, decrypt(protector, formatted, ID));
        }
    }

    @Test
    void encryptDecrypt_ACharBufferPlaintext_NeverNeedsAString() {
        try (var protector = create()) {
            var secret = "s3cret".toCharArray();
            var formatted = protector.encrypt(CharBuffer.wrap(secret), ID);
            ArrayUtility.zeroMemory(secret);

            var result = new char[protector.getMaxDecryptedLength(formatted)];
            var written = protector.decrypt(formatted, ID, result);

            assertEquals("s3cret", new String(result, 0, written));
        }
    }

    @Test
    void valuesLargerThanOnePage_RoundTrip() {
        // 1,500 × (2 + 1 + 6 + 1) = 15,000 UTF-8 bytes.
        var large = "é-秘密-".repeat(1500);
        try (var protector = create()) {
            assertEquals(large, decrypt(protector, protector.encrypt(large, "Big:Secret"), "Big:Secret"));
        }
    }

    @Test
    void encryptAndDecrypt_WithAnEmptySecretIdentifier_Throw() {
        try (var protector = create()) {
            var formatted = protector.encrypt("hello", ID);

            assertThrows(IllegalArgumentException.class, () -> protector.encrypt("hello", ""));
            assertThrows(IllegalArgumentException.class, () -> protector.decrypt(formatted, "", new char[16]));
        }
    }

    @Test
    void encryptAndDecrypt_WithASecretIdentifierThatIsNotValidUtf16_Throw() {
        try (var protector = create()) {
            var formatted = protector.encrypt("hello", ID);

            assertThrows(IllegalArgumentException.class, () -> protector.encrypt("hello", "Key\uD800"));
            assertThrows(IllegalArgumentException.class, () -> protector.decrypt(formatted, "Key\uD800", new char[16]));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"pipeline:secret", "PIPELINE:SECRET"})
    void secretIdentifiers_AreCaseInsensitive_LikeConfigurationKeys(String lookup) {
        try (var protector = create()) {
            assertEquals("hello", decrypt(protector, protector.encrypt("hello", ID), lookup));
        }
    }

    @Test
    void aLongSecretIdentifier_RoundTrips() {
        var longId = IntStream.range(0, 60).mapToObj(i -> "Section" + i).collect(Collectors.joining(":"));
        try (var protector = create()) {
            var formatted = protector.encrypt("hello", longId);

            assertEquals("hello", decrypt(protector, formatted, longId));
            assertThrows(CryptographicException.class, () -> protector.decrypt(formatted, longId + "X", new char[16]));
        }
    }

    @Test
    void keyVersion_IsStampedOnEveryValue() {
        try (var protector = create(42)) {
            var formatted = protector.encrypt("hello", ID);

            assertEquals(42, protector.getKeyVersion());
            assertTrue(formatted.startsWith("enc::v42::"));
            assertFalse(formatted.contains("hello"));
        }
    }

    @Test
    void encrypt_SameValueTwice_ProducesDifferentOutput() {
        try (var protector = create()) {
            assertNotEquals(protector.encrypt("hello", ID), protector.encrypt("hello", ID));
        }
    }

    @Test
    void oneKey_ProtectsManySecrets_EachBoundToItsOwnIdentifier() {
        try (var protector = create()) {
            var adminValue = protector.encrypt("admin-secret", "ConnectionStrings:Admin");
            var reportingValue = protector.encrypt("reporting-secret", "ConnectionStrings:Reporting");

            assertEquals("admin-secret", decrypt(protector, adminValue, "ConnectionStrings:Admin"));
            assertEquals("reporting-secret", decrypt(protector, reportingValue, "ConnectionStrings:Reporting"));
        }
    }

    @Test
    void decrypt_AValueMovedToAnotherIdentifier_FailsAuthentication() {
        try (var protector = create()) {
            var adminValue = protector.encrypt("admin-secret", "ConnectionStrings:Admin");

            assertThrows(AuthenticationTagMismatchException.class,
                    () -> protector.decrypt(adminValue, "ConnectionStrings:Reporting", new char[32]));
        }
    }

    @Test
    void decrypt_OfAValueStampedWithAnotherVersion_ThrowsNoSuchElement() {
        try (var protector = create()) {
            var formatted = protector.encrypt("hello", ID).replace("::v" + VERSION + "::", "::v99::");

            assertThrows(NoSuchElementException.class, () -> protector.decrypt(formatted, ID, new char[16]));
        }
    }

    @Test
    void decrypt_UnderADifferentInstance_Fails() {
        try (var writer = create(); var reader = create()) {
            var formatted = writer.encrypt("hello", ID);

            assertThrows(CryptographicException.class, () -> reader.decrypt(formatted, ID, new char[16]));
        }
    }

    @Test
    void decrypt_WithMalformedInput_ThrowsTheFormatProvidersException() {
        try (var protector = create()) {
            assertThrows(EncryptedFormatException.class, () -> protector.decrypt("not-a-valid-format", ID, new char[16]));
        }
    }

    @Test
    void encryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips() {
        var original = HkdfGuardTelemetry.DATA_PROTECTION.isSensitiveLoggingEnabled();
        HkdfGuardTelemetry.DATA_PROTECTION.setSensitiveLoggingEnabled(true);
        try (var capture = new SpanCapture(); var protector = create()) {
            assertEquals("hello", decrypt(protector, protector.encrypt("hello", ID), ID));
        } finally {
            HkdfGuardTelemetry.DATA_PROTECTION.setSensitiveLoggingEnabled(original);
        }
    }

    @Test
    void getKeyAsBase64_EncodesTheKey_AsAReadOnlyViewOfOneBuffer() {
        var key = FakeKeyWrapper.randomKey();
        try (var protector = new AesGcmPipelineDataProtectorImpl(new TestFormatProvider(), VERSION, key.clone())) {
            var first = protector.getKeyAsBase64();
            var second = protector.getKeyAsBase64();

            assertEquals(Base64.getEncoder().encodeToString(key), first.toString());
            assertTrue(first.isReadOnly());
            assertThrows(ReadOnlyBufferException.class, () -> first.put(0, 'x'));
            assertEquals(first, second);
        }
    }

    @Test
    void getKeyAsBase64_IsTheKeyThatEncryptedTheValues() {
        try (var pipeline = create()) {
            var formatted = pipeline.encrypt("hello", ID);
            var key = Base64.getDecoder().decode(pipeline.getKeyAsBase64().toString());

            try (var reader = new AesGcmPipelineDataProtectorImpl(new TestFormatProvider(), VERSION, key)) {
                assertEquals("hello", decrypt(reader, formatted, ID));
            }
        }
    }

    @Test
    void encrypt_CountsAgainstTheKeysBudgetAndStopsAtTheLimit() {
        try (var protector = new AesGcmPipelineDataProtectorImpl(new TestFormatProvider(), VERSION,
                FakeKeyWrapper.randomKey(), new EncryptionBudget(1, 2))) {
            var formatted = protector.encrypt("one", ID);
            protector.encrypt("two", ID);

            assertEquals(2, protector.getEncryptionCount());
            assertThrows(CryptographicException.class, () -> protector.encrypt("three", ID));
            assertEquals("one", decrypt(protector, formatted, ID));
        }
    }

    @Test
    void close_ZeroesTheKeyAndItsBase64Form() {
        var key = FakeKeyWrapper.randomKey();
        var protector = new AesGcmPipelineDataProtectorImpl(new TestFormatProvider(), VERSION, key);
        protector.getKeyAsBase64();
        var base64 = protector.base64Buffer();

        protector.close();

        assertArrayEquals(new byte[32], key);
        assertArrayEquals(new char[base64.length], base64);
    }

    @Test
    void close_CalledTwice_DoesNotThrow() {
        var protector = create();

        protector.close();
        assertDoesNotThrow(protector::close);
    }

    @Test
    void afterClose_EveryOperationThrowsIllegalState() {
        var protector = create();
        var formatted = protector.encrypt("hello", ID);
        protector.close();

        assertThrows(IllegalStateException.class, () -> protector.encrypt("hello", ID));
        assertThrows(IllegalStateException.class, () -> protector.decrypt(formatted, ID, new char[16]));
        assertThrows(IllegalStateException.class, protector::getKeyAsBase64);
    }

    @Test
    void constructor_WithNullFormatProvider_Throws() {
        assertThrows(NullPointerException.class, () -> new AesGcmPipelineDataProtectorImpl(null, VERSION));
    }

    @Test
    void theStoredValue_IsNonceCiphertextAndTag_ForThePlaintextsUtf8Bytes() {
        try (var protector = create()) {
            var formatted = protector.encrypt("héllo", ID);
            var ciphertext = new TestFormatProvider().parse(formatted).value();

            assertEquals(12 + "héllo".getBytes(StandardCharsets.UTF_8).length + 16, ciphertext.length);
        }
    }
}
