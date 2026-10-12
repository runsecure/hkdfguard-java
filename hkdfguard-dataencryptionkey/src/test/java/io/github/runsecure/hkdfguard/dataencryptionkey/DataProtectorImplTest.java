package io.github.runsecure.hkdfguard.dataencryptionkey;

import static io.github.runsecure.hkdfguard.dataencryptionkey.TestKeys.utf8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException;
import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException;
import io.github.runsecure.hkdfguard.abstractions.ProtectedCacheBase;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** DataProtectorImpl's behaviour, reached as callers reach it: through KeyRingImpl.createProtector. */
class DataProtectorImplTest {
    private static KeyRingImpl ringWithOneKey() {
        var ring = new KeyRingImpl(new DefaultFormatProviderImpl());
        ring.add(1, TestKeys.newKey());
        return ring;
    }

    @ParameterizedTest
    @ValueSource(strings = {"HkdfGuard.Cache:", "HkdfGuard.Cache:SECRET"})
    void createProtector_RefusesTheCachesReservedPrefix(String name) {
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            var ex = assertThrows(IllegalArgumentException.class, () -> ring.createProtector(name));

            assertTrue(ex.getMessage().contains("reserved"));
        }
    }

    @Test
    void createProtector_RefusesANameThatIsNotValidUtf16() {
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            assertThrows(IllegalArgumentException.class, () -> ring.createProtector("purpose\uD800"));
            assertThrows(IllegalArgumentException.class, () -> ring.createProtector("purpose\uDC00tail"));
        }
    }

    @Test
    void createProtector_RefusesAnEmptyOrNullName() {
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            assertThrows(IllegalArgumentException.class, () -> ring.createProtector(""));
            assertThrows(NullPointerException.class, () -> ring.createProtector(null));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"hkdfguard.cache:secret", "MyApp.Cache:secret", "HkdfGuard.EncryptedConfiguration:ConnectionStrings:Admin"})
    void createProtector_AcceptsEveryOtherName(String name) {
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            assertNotNull(ring.createProtector(name));
        }
    }

    @Test
    void aProtector_CannotDecryptACacheEntry_BecauseItCanNeverShareItsAad() {
        try (var ring = ringWithOneKey()) {
            var cacheAad = ProtectedCacheBase.aadFor("secret");

            // The only protector name whose AAD equals the cache entry's is the reserved one.
            assertArrayEquals(utf8("HkdfGuard.Cache:SECRET"), cacheAad);
            assertThrows(IllegalArgumentException.class, () -> ring.createProtector("HkdfGuard.Cache:SECRET"));
        }
    }

    @Test
    void encrypt_OnAnEmptyRing_ThrowsIllegalState() {
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            assertThrows(IllegalStateException.class, () -> ring.createProtector("purpose").encrypt("hello"));
        }
    }

    @Test
    void decrypt_WithMalformedInput_ThrowsTheFormatException() {
        try (var ring = ringWithOneKey()) {
            assertThrows(EncryptedFormatException.class, () -> ring.createProtector("purpose").decrypt("not-a-valid-format", new char[16]));
        }
    }

    @Test
    void decrypt_ForAnUnregisteredVersion_ThrowsNoSuchElement() {
        try (var ring = ringWithOneKey()) {
            var protector = ring.createProtector("purpose");
            var tampered = protector.encrypt("hello").replace("::v1::", "::v99::");

            assertThrows(NoSuchElementException.class, () -> protector.decrypt(tampered, new char[16]));
        }
    }

    @Test
    void encryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips() {
        TestKeys.withSensitiveLogging(() -> {
            try (var ring = ringWithOneKey()) {
                var protector = ring.createProtector("purpose");
                var result = new char[16];

                assertEquals("hello", new String(result, 0, protector.decrypt(protector.encrypt("hello"), result)));
            }
        });
    }

    @Test
    void decrypt_UnderADifferentProtectorName_FailsAuthentication() {
        try (var ring = ringWithOneKey()) {
            var formatted = ring.createProtector("purpose-a").encrypt("hello");

            assertThrows(AuthenticationTagMismatchException.class, () -> ring.createProtector("purpose-b").decrypt(formatted, new char[16]));
        }
    }

    @Test
    void encrypt_WhenTheKeyThrows_PropagatesTheException() {
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            ring.add(1, new ThrowingKey());

            assertThrows(IllegalStateException.class, () -> ring.createProtector("purpose").encrypt("hello"));
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 4096, -1})
    void largeAndSmallValues_RoundTrip(int length) {
        // 15,000 UTF-8 bytes, mixing 1-, 2- and 3-byte characters, when length is negative.
        var plaintext = length < 0 ? "é-秘密-".repeat(1500) : "x".repeat(length);
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl(100_000))) {
            ring.add(1, TestKeys.newKey());
            var protector = ring.createProtector("large");

            var formatted = protector.encrypt(plaintext);
            var result = new char[protector.getMaxDecryptedLength(formatted)];

            assertEquals(plaintext, new String(result, 0, protector.decrypt(formatted, result)));
        }
    }

    // Throws without zeroing its input - DataProtectorImpl must zero the UTF-8 plaintext itself.
    private static final class ThrowingKey implements DataEncryptionKey {
        @Override
        public byte[] encrypt(byte[] plaintext) {
            throw new IllegalStateException("encrypt failed");
        }

        @Override
        public byte[] encrypt(byte[] plaintext, byte[] aad) {
            throw new IllegalStateException("encrypt failed");
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
            throw new UnsupportedOperationException();
        }
    }
}
