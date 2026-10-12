package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class AesGcmCryptoSessionTest {
    private static final HexFormat HEX = HexFormat.of();

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void encryptDecrypt_RoundTrips() {
        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            var encrypted = new byte[11 + 28];

            var written = cipher.encrypt(utf8("hello world"), encrypted);
            assertEquals(encrypted.length, written);

            var decrypted = new byte[11];
            assertEquals(11, cipher.decrypt(encrypted, decrypted));
            assertArrayEquals(utf8("hello world"), decrypted);
        }
    }

    @Test
    void encryptDecrypt_RoundTrips_WithAad() {
        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            var encrypted = new byte[11 + 28];
            cipher.encrypt(utf8("hello world"), utf8("context"), encrypted);

            var decrypted = new byte[11];
            cipher.decrypt(encrypted, utf8("context"), decrypted);

            assertArrayEquals(utf8("hello world"), decrypted);
        }
    }

    @Test
    void decrypt_TheNistGcmTestVector_MatchesTheStandardLayout() {
        // NIST GCM spec, test case 16 (AES-256, 96-bit IV, with AAD), laid out as this library
        // stores it - nonce | ciphertext | tag - the same layout the .NET library writes.
        var key = HEX.parseHex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        var plaintext = HEX.parseHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        var aad = HEX.parseHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        var stored = HEX.parseHex("cafebabefacedbaddecaf888"
                + "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                + "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
                + "76fc6ece0f4e1768cddf8853bb2d551b");

        try (var cipher = new AesGcmCryptoSession(key)) {
            var decrypted = new byte[plaintext.length];
            assertEquals(plaintext.length, cipher.decrypt(stored, aad, decrypted));
            assertArrayEquals(plaintext, decrypted);
        }
    }

    @Test
    void decrypt_WithWrongAad_ThrowsAndLeavesNoPlaintextBehind() {
        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            var encrypted = new byte[11 + 28];
            cipher.encrypt(utf8("hello world"), utf8("correct-aad"), encrypted);

            var decrypted = new byte[11];
            assertThrows(AuthenticationTagMismatchException.class, () -> cipher.decrypt(encrypted, utf8("wrong-aad"), decrypted));
            assertArrayEquals(new byte[11], decrypted);
        }
    }

    @Test
    void decrypt_WithTamperedCiphertext_Throws() {
        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            var encrypted = new byte[11 + 28];
            cipher.encrypt(utf8("hello world"), encrypted);
            encrypted[15] ^= (byte) 0xFF;

            assertThrows(AuthenticationTagMismatchException.class, () -> cipher.decrypt(encrypted, new byte[11]));
        }
    }

    @Test
    void encrypt_WithTooSmallResultBuffer_Throws() {
        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(utf8("hello world"), new byte[11]));
        }
    }

    @Test
    void decrypt_WithTooShortOrEmptyCiphertext_Throws() {
        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(new byte[10], new byte[4]));
            assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(Arrays.copyOf(FakeKeyWrapper.randomKey(), 10), new byte[4]));
            assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(new byte[0], new byte[4]));
        }
    }

    @Test
    void decrypt_WithTooSmallResultBuffer_Throws() {
        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            var encrypted = new byte[11 + 28];
            cipher.encrypt(utf8("hello world"), encrypted);

            assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(encrypted, new byte[10]));
        }
    }

    @Test
    void constructor_WithInvalidKeySizeOrAllZeroKey_Throws() {
        assertThrows(IllegalArgumentException.class, () -> new AesGcmCryptoSession(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}));
        assertThrows(IllegalArgumentException.class, () -> new AesGcmCryptoSession(new byte[32]));
    }

    @Test
    void encrypt_WithAllZeroPlaintext_RoundTrips() {
        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            var encrypted = new byte[11 + 28];
            var written = cipher.encrypt(new byte[11], encrypted);

            var decrypted = new byte[11];
            assertEquals(11, cipher.decrypt(Arrays.copyOf(encrypted, written), decrypted));
            assertArrayEquals(new byte[11], decrypted);
        }
    }

    @Test
    void encrypt_WithEmptyPlaintext_RoundTripsToAnAuthenticatedEmptyMessage() {
        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            var encrypted = new byte[28];

            assertEquals(28, cipher.encrypt(new byte[0], utf8("aad"), encrypted));
            assertEquals(0, cipher.decrypt(encrypted, utf8("aad"), new byte[0]));
            assertThrows(AuthenticationTagMismatchException.class, () -> cipher.decrypt(encrypted, utf8("other"), new byte[0]));
        }
    }

    @Test
    void close_ZeroesTheKey() {
        var key = FakeKeyWrapper.randomKey();
        var cipher = new AesGcmCryptoSession(key);

        cipher.close();

        assertArrayEquals(new byte[32], key);
    }

    @Test
    void close_ThenEncrypt_Throws() {
        var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey());
        cipher.close();

        assertThrows(IllegalStateException.class, () -> cipher.encrypt(utf8("hello"), new byte[33]));
    }

    @Test
    void sequentialOperations_ReuseTheOneCipherInstance() {
        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            var encrypted = new byte[11 + 28];
            var decrypted = new byte[11];

            for (var i = 0; i < 50; i++) {
                cipher.encrypt(utf8("hello world"), encrypted);
                cipher.decrypt(encrypted, decrypted);
            }

            assertEquals(1, cipher.instanceCount());
            assertEquals(1, cipher.idleInstanceCount());
        }
    }

    @Test
    void rent_WhenNoInstanceIsIdle_BuildsAnotherAndReturnPoolsIt() {
        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            var first = cipher.rent();
            var second = cipher.rent();

            assertNotSame(first, second);
            assertEquals(2, cipher.instanceCount());
            assertEquals(0, cipher.idleInstanceCount());

            cipher.returnCipher(first);
            cipher.returnCipher(second);

            assertEquals(2, cipher.idleInstanceCount());
        }
    }

    @Test
    void concurrentOperations_EachUseTheirOwnInstance_AndEveryResultRoundTripsUnderItsOwnNonce() throws InterruptedException {
        final int workers = 8;
        final int perWorker = 500;
        var nonces = ConcurrentHashMap.<String>newKeySet();
        var failure = new AtomicReference<Throwable>();
        var start = new CountDownLatch(1);
        var threads = new ArrayList<Thread>();

        try (var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            for (var w = 0; w < workers; w++) {
                final int worker = w;
                threads.add(Thread.ofPlatform().start(() -> {
                    try {
                        start.await();
                        var encrypted = new byte[4 + 28];
                        var decrypted = new byte[4];
                        for (var i = 0; i < perWorker; i++) {
                            var value = worker * perWorker + i;
                            var aad = ByteBuffer.allocate(4).putInt(worker).array();

                            cipher.encrypt(ByteBuffer.allocate(4).putInt(value).array(), aad, encrypted);
                            if (!nonces.add(HEX.formatHex(encrypted, 0, 12)))
                                throw new AssertionError("nonce repeated");

                            cipher.decrypt(encrypted, aad, decrypted);
                            if (ByteBuffer.wrap(decrypted).getInt() != value)
                                throw new AssertionError("wrong plaintext");
                        }
                    } catch (Throwable t) {
                        failure.compareAndSet(null, t);
                    }
                }));
            }
            start.countDown();
            for (var thread : threads)
                thread.join();

            assertNull(failure.get());
            assertEquals(workers * perWorker, nonces.size());
            assertTrue(cipher.instanceCount() >= 1 && cipher.instanceCount() <= workers);
            assertEquals(cipher.instanceCount(), cipher.idleInstanceCount());
        }
    }

    @Test
    void close_WhileAnInstanceIsRented_ReleasesItOnReturnInsteadOfPoolingIt() {
        var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey());
        var rented = cipher.rent();

        cipher.close();
        cipher.returnCipher(rented);

        assertEquals(0, cipher.idleInstanceCount());
        assertNull(cipher.tryRent());
        assertThrows(IllegalStateException.class, cipher::rent);
    }

    @Test
    void tryEncrypt_OnAClosedSession_ReturnsMinusOne_LeavingPlaintextAndTheCountUntouched() {
        var budget = new EncryptionBudget();
        var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey(), budget, null);
        cipher.close();
        var plaintext = utf8("still here");

        assertEquals(-1, cipher.tryEncrypt(plaintext, new byte[0], new byte[64]));

        assertArrayEquals(utf8("still here"), plaintext); // intact, so a caller can retry on the current session
        assertEquals(0, budget.getCount());
    }

    @Test
    void encrypt_OnAClosedSession_Throws_AndStillZeroesThePlaintext() {
        var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey());
        cipher.close();
        var plaintext = utf8("secret");

        assertThrows(IllegalStateException.class, () -> cipher.encrypt(plaintext, new byte[64]));

        assertArrayEquals(new byte[6], plaintext);
    }

    @Test
    void tryDecrypt_OnAClosedSession_ReturnsMinusOne_AndDecryptThrows() {
        var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey());
        var ciphertext = new byte[4 + 28];
        cipher.encrypt(utf8("abcd"), ciphertext);
        cipher.close();

        assertEquals(-1, cipher.tryDecrypt(ciphertext, new byte[0], new byte[4]));
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(ciphertext, new byte[4]));
    }

    @Test
    void close_Twice_IsSafe() {
        var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey());

        cipher.close();
        cipher.close();

        assertTrue(cipher.isClosed());
        assertThrows(IllegalStateException.class, cipher::rent);
    }

    @Test
    void encryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips() {
        var original = HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.isSensitiveLoggingEnabled();
        HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.setSensitiveLoggingEnabled(true);
        try (var capture = new SpanCapture(); var cipher = new AesGcmCryptoSession(FakeKeyWrapper.randomKey())) {
            var encrypted = new byte[11 + 28];
            var written = cipher.encrypt(utf8("hello world"), utf8("aad"), encrypted);

            var decrypted = new byte[11];
            cipher.decrypt(Arrays.copyOf(encrypted, written), utf8("aad"), decrypted);

            assertArrayEquals(utf8("hello world"), decrypted);
            assertFalse(capture.spans(io.github.runsecure.hkdfguard.diagnostics.SpanNames.CryptoProviderAesGcm256.ENCRYPT).getFirst().getEvents().isEmpty());
        } finally {
            HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.setSensitiveLoggingEnabled(original);
        }
    }
}
