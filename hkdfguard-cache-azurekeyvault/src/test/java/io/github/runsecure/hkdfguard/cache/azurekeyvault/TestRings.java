package io.github.runsecure.hkdfguard.cache.azurekeyvault;

import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.DataEncryptionKeyImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;

/** Real key rings of real AES-256-GCM keys for the cache to encrypt under (from hkdfguard-cache's tests). */
final class TestRings {
    private static final SecureRandom RANDOM = new SecureRandom();

    private TestRings() {
    }

    static String text(byte[] bytes, int length) {
        return new String(bytes, 0, length, StandardCharsets.UTF_8);
    }

    /** A real key over a fixed random DEK. */
    static DataEncryptionKey newKey() {
        var key = new byte[32];
        RANDOM.nextBytes(key);
        return new DataEncryptionKeyImpl(Futures.await(AesGcmCryptoProviderImpl.createAsync(
                new FixedKeyWrapper(key), "wrapped".getBytes(StandardCharsets.UTF_8), 60)));
    }

    /** A ring holding one fresh key as version 1, its current version. */
    static KeyRingImpl ring() {
        var ring = new KeyRingImpl(new DefaultFormatProviderImpl());
        ring.add(1, newKey());
        return ring;
    }

    /** Runs {@code body} with the shared Cache sensitive-logging flag set, restoring it after. */
    static void withSensitiveLogging(Runnable body) {
        var original = HkdfGuardTelemetry.CACHE.isSensitiveLoggingEnabled();
        HkdfGuardTelemetry.CACHE.setSensitiveLoggingEnabled(true);
        try {
            body.run();
        } finally {
            HkdfGuardTelemetry.CACHE.setSensitiveLoggingEnabled(original);
        }
    }

    /** A KeyWrapper that always reveals the same fixed key. */
    static final class FixedKeyWrapper implements KeyWrapper {
        private final byte[] key;

        FixedKeyWrapper(byte[] key) {
            this.key = key;
        }

        @Override
        public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
            System.arraycopy(key, 0, result, 0, key.length);
            return CompletableFuture.completedFuture(key.length);
        }

        // Test double: plain file I/O. A real key wrapper must refuse a key file another account
        // could have written or replaced.
        @Override
        public CompletableFuture<byte[]> readKeyFileAsync(Path path) {
            try {
                return CompletableFuture.completedFuture(Files.readAllBytes(path));
            } catch (IOException | RuntimeException e) {
                return CompletableFuture.failedFuture(e);
            }
        }

        @Override
        public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
            throw new UnsupportedOperationException();
        }
    }
}
