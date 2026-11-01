package io.github.runsecure.hkdfguard.dataencryptionkey;

import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.await;
import static io.github.runsecure.hkdfguard.dataencryptionkey.TestKeys.utf8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException;
import io.github.runsecure.hkdfguard.abstractions.CryptoProvider;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.EncryptionLimitReachedException;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderImpl;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class DataEncryptionKeyImplTest {
    private static DataEncryptionKeyImpl key(TestKeys.FakeKeyWrapper wrapper) {
        return new DataEncryptionKeyImpl(await(AesGcmCryptoProviderImpl.createAsync(wrapper, utf8("wrapped"), 60)));
    }

    @Test
    void encryptDecrypt_RoundTrips_AndTheCiphertextIsExactlySized() {
        try (var key = TestKeys.newKey()) {
            var expected = utf8("top secret");

            var encrypted = key.encrypt(expected.clone());
            assertEquals(expected.length + 12 + 16, encrypted.length);

            var decrypted = new byte[expected.length];
            assertEquals(expected.length, key.decrypt(encrypted, decrypted));
            assertArrayEquals(expected, decrypted);
        }
    }

    @Test
    void encryptDecrypt_WithAad_RoundTrips() {
        try (var key = TestKeys.newKey()) {
            var encrypted = key.encrypt(utf8("top secret"), utf8("context"));

            var decrypted = new byte[10];
            var length = key.decrypt(encrypted, utf8("context"), decrypted);

            assertArrayEquals(utf8("top secret"), Arrays.copyOf(decrypted, length));
        }
    }

    @Test
    void decrypt_WithMismatchedAad_Throws() {
        try (var key = TestKeys.newKey()) {
            var encrypted = key.encrypt(utf8("top secret"), utf8("context-a"));

            assertThrows(AuthenticationTagMismatchException.class, () -> key.decrypt(encrypted, utf8("context-b"), new byte[10]));
        }
    }

    @Test
    void encryptDecrypt_WithSensitiveLoggingEnabled_StillRoundTrips() {
        TestKeys.withSensitiveLogging(() -> {
            try (var capture = new SpanCapture(); var key = TestKeys.newKey()) {
                var encrypted = key.encrypt(utf8("top secret"));
                var decrypted = new byte[10];

                assertArrayEquals(utf8("top secret"), Arrays.copyOf(decrypted, key.decrypt(encrypted, decrypted)));
                assertEquals(1, capture.spans(io.github.runsecure.hkdfguard.diagnostics.SpanNames.DataProtection.KEY_WRAPPED_KEY_ENCRYPT).size());
            }
        });
    }

    @Test
    void encrypt_ZeroesThePlaintext_AsTheProviderContractPromises() {
        try (var key = TestKeys.newKey()) {
            var plaintext = utf8("top secret");

            key.encrypt(plaintext, utf8("aad"));

            assertArrayEquals(new byte[plaintext.length], plaintext);
        }
    }

    @Test
    void encryptAndDecrypt_ReuseTheCachedSessionAcrossCalls() {
        var wrapper = new TestKeys.FakeKeyWrapper(TestKeys.randomKey());
        try (var key = key(wrapper)) {
            var one = key.encrypt(utf8("one"));
            var two = key.encrypt(utf8("two"));

            key.decrypt(one, new byte[3]);
            key.decrypt(two, new byte[3]);

            assertEquals(1, wrapper.unwrapCallCount.get());
        }
    }

    @Test
    void close_ClosesTheProvider() {
        var key = TestKeys.newKey();

        key.close();

        assertThrows(IllegalStateException.class, () -> key.encrypt(utf8("top secret")));
    }

    @Test
    void closeAsync_ClosesTheProvider() {
        var key = TestKeys.newKey();

        await(key.closeAsync());

        assertThrows(IllegalStateException.class, () -> key.encrypt(utf8("top secret")));
    }

    @Test
    void closeAndCloseAsync_TogetherCloseTheProviderOnce() {
        var provider = new CountingCloseProvider();
        var key = new DataEncryptionKeyImpl(provider);

        await(key.closeAsync());
        await(key.closeAsync());
        key.close();

        assertEquals(1, provider.closeAsyncCount);
        assertEquals(0, provider.closeCount);

        var other = new CountingCloseProvider();
        var syncKey = new DataEncryptionKeyImpl(other);
        syncKey.close();
        syncKey.close();
        assertEquals(1, other.closeCount);
    }

    @Test
    void encrypt_WhenTheProviderOverAllocates_TrimsToWhatWasWritten() {
        try (var key = new DataEncryptionKeyImpl(new OverAllocatingProvider())) {
            assertArrayEquals(utf8("abc"), key.encrypt(utf8("abc")));
        }
    }

    // --- Deadline -------------------------------------------------------------------------------

    private static DataEncryptionKeyImpl keyWithDeadline(EncryptionDeadline deadline, java.time.Clock clock) {
        var provider = await(AesGcmCryptoProviderImpl.createAsync(new TestKeys.FakeKeyWrapper(TestKeys.randomKey()), utf8("wrapped"), 60));
        return new DataEncryptionKeyImpl(provider, deadline, clock);
    }

    @Test
    void encrypt_StopsAtItsDeadline_ZeroingThePlaintext_ButKeepsDecrypting() {
        var calls = Collections.synchronizedList(new ArrayList<String>());
        var now = Instant.now();
        var clock = new TestKeys.MutableClock(now);
        var deadline = new EncryptionDeadline(now.plusSeconds(1), now.plusSeconds(2), "rotate me", () -> calls.add("warn"), () -> calls.add("expired"));
        try (var key = keyWithDeadline(deadline, clock)) {
            var ciphertext = key.encrypt(utf8("before"));
            assertFalse(key.checkDeadline(now));
            assertEquals(List.of(), calls);

            clock.set(now.plusMillis(1500));
            key.encrypt(utf8("warned"));
            key.encrypt(utf8("warned again"));
            assertEquals(List.of("warn"), calls);

            clock.set(now.plusSeconds(2));
            var plaintext = utf8("refused");
            var refused = assertThrows(EncryptionLimitReachedException.class, () -> key.encrypt(plaintext));
            assertEquals("rotate me", refused.getMessage());
            assertTrue(CryptographicException.class.isInstance(refused));
            assertArrayEquals(new byte[plaintext.length], plaintext);
            assertThrows(EncryptionLimitReachedException.class, () -> key.encrypt(utf8("refused again")));
            assertEquals(List.of("warn", "expired"), calls);

            var result = new byte[6];
            key.decrypt(ciphertext, result);
            assertArrayEquals(utf8("before"), result);
        }
    }

    @Test
    void checkDeadline_AnnouncesExpiryOnce_EvenWhenTheWarningWasSkipped_AndIgnoresAThrowingCallback() {
        var expired = new AtomicInteger();
        var deadline = new EncryptionDeadline(Instant.EPOCH, Instant.EPOCH.plusMillis(1), "old",
                () -> {
                    throw new IllegalStateException("never called");
                },
                () -> {
                    expired.incrementAndGet();
                    throw new IllegalStateException("bad logger");
                });
        try (var key = new DataEncryptionKeyImpl(await(AesGcmCryptoProviderImpl.createAsync(
                new TestKeys.FakeKeyWrapper(TestKeys.randomKey()), utf8("wrapped"), 60)), deadline)) {
            assertThrows(EncryptionLimitReachedException.class, () -> key.encrypt(utf8("x")));
            assertThrows(EncryptionLimitReachedException.class, () -> key.encrypt(utf8("x")));
            assertEquals(1, expired.get());
        }
    }

    @Test
    void checkDeadline_UnderConcurrentEncrypts_AnnouncesEachOnlyOnce() throws InterruptedException {
        var warnings = new AtomicInteger();
        var expiries = new AtomicInteger();
        var now = Instant.now();
        var clock = new TestKeys.MutableClock(now.plusMillis(1500));
        var deadline = new EncryptionDeadline(now.plusSeconds(1), now.plusSeconds(2), "late", warnings::incrementAndGet, expiries::incrementAndGet);
        try (var key = keyWithDeadline(deadline, clock)) {
            for (var stage = 0; stage < 2; stage++) {
                var start = new CountDownLatch(1);
                var threads = new ArrayList<Thread>();
                for (var i = 0; i < 8; i++)
                    threads.add(Thread.ofPlatform().start(() -> {
                        try {
                            start.await();
                            for (var j = 0; j < 50; j++)
                                key.checkDeadline(clock.instant());
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }));
                start.countDown();
                for (var thread : threads)
                    thread.join();
                clock.advance(Duration.ofSeconds(1));
            }
            assertEquals(1, warnings.get());
            assertEquals(1, expiries.get());
        }
    }

    @Test
    void encrypt_WithoutADeadline_IsNotLimited() {
        try (var key = TestKeys.newKey()) {
            assertNull(key.getDeadline());
            assertFalse(key.checkDeadline(Instant.MAX));
            assertEquals(5 + 28, key.encrypt(utf8("hello")).length);
        }
    }

    private static class CountingCloseProvider implements CryptoProvider {
        int closeCount;
        int closeAsyncCount;

        @Override
        public int encrypt(byte[] plaintext, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int encrypt(byte[] plaintext, byte[] aad, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int getEncryptedAllocationLength(int length) {
            return length;
        }

        @Override
        public int getDecryptedAllocationLength(int length) {
            return length;
        }

        @Override
        public CompletableFuture<Void> closeAsync() {
            closeAsyncCount++;
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public void close() {
            closeCount++;
        }
    }

    // Asks for 10 spare bytes and "encrypts" by copying - stands in for a provider whose exact
    // ciphertext size isn't known up front.
    private static final class OverAllocatingProvider extends CountingCloseProvider {
        @Override
        public int encrypt(byte[] plaintext, byte[] aad, byte[] result) {
            System.arraycopy(plaintext, 0, result, 0, plaintext.length);
            return plaintext.length;
        }

        @Override
        public int getEncryptedAllocationLength(int length) {
            return length + 10;
        }
    }
}
