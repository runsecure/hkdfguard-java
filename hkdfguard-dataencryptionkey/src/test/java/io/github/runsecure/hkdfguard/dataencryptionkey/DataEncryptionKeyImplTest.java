package io.github.runsecure.hkdfguard.dataencryptionkey;

import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.await;
import static io.github.runsecure.hkdfguard.dataencryptionkey.TestKeys.utf8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException;
import io.github.runsecure.hkdfguard.abstractions.CryptoProvider;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderImpl;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
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
