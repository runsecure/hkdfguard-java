package io.github.runsecure.hkdfguard.dataencryptionkey;

import io.github.runsecure.hkdfguard.abstractions.CryptoProvider;
import io.github.runsecure.hkdfguard.abstractions.CryptoProviderFactory;
import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderImpl;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/** Shared test doubles: a fixed-key wrapper, a recording provider factory, and helpers. */
final class TestKeys {
    private static final SecureRandom RANDOM = new SecureRandom();

    private TestKeys() {
    }

    static byte[] randomKey() {
        var key = new byte[32];
        RANDOM.nextBytes(key);
        return key;
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** A real AES-256-GCM key over a fixed random DEK. */
    static DataEncryptionKeyImpl newKey() {
        return new DataEncryptionKeyImpl(Futures.await(AesGcmCryptoProviderImpl.createAsync(new FakeKeyWrapper(randomKey()), utf8("wrapped"), 60)));
    }

    /** Runs {@code body} with the shared DataProtection sensitive-logging flag set, restoring it after. */
    static void withSensitiveLogging(Runnable body) {
        var original = HkdfGuardTelemetry.DATA_PROTECTION.isSensitiveLoggingEnabled();
        HkdfGuardTelemetry.DATA_PROTECTION.setSensitiveLoggingEnabled(true);
        try {
            body.run();
        } finally {
            HkdfGuardTelemetry.DATA_PROTECTION.setSensitiveLoggingEnabled(original);
        }
    }

    /**
     * A KeyWrapper that always reveals/generates the same fixed key, counting calls - isolates
     * key-ring tests from native KMS machinery while still exercising real AES-GCM.
     */
    static class FakeKeyWrapper implements KeyWrapper {
        private final byte[] key;
        final AtomicInteger unwrapCallCount = new AtomicInteger();
        final AtomicInteger generateAndWrapCallCount = new AtomicInteger();
        volatile RuntimeException throwOnUnwrap;

        FakeKeyWrapper(byte[] key) {
            this.key = key;
        }

        @Override
        public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
            throw new UnsupportedOperationException("FakeKeyWrapper only reveals.");
        }

        @Override
        public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
            unwrapCallCount.incrementAndGet();
            var failure = throwOnUnwrap;
            if (failure != null)
                throw failure;
            System.arraycopy(key, 0, result, 0, key.length);
            return CompletableFuture.completedFuture(key.length);
        }

        // Test double: plain file I/O. A real key wrapper must refuse a key file another account could
        // have written or replaced (the native one reads through hkdfguard_open_file).
        @Override
        public CompletableFuture<byte[]> readKeyFileAsync(java.nio.file.Path path) {
            try {
                return CompletableFuture.completedFuture(java.nio.file.Files.readAllBytes(path));
            } catch (java.io.IOException | RuntimeException e) {
                return CompletableFuture.failedFuture(e);
            }
        }

        @Override
        public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
            generateAndWrapCallCount.incrementAndGet();
            System.arraycopy(key, 0, result, 0, key.length);
            return CompletableFuture.completedFuture(key.length);
        }
    }

    /**
     * Delegates to a real AES-GCM factory (so callers get working providers) while recording the
     * arguments of every call.
     */
    static class RecordingCryptoProviderFactory implements CryptoProviderFactory {
        private final AesGcmCryptoProviderFactoryImpl inner = new AesGcmCryptoProviderFactoryImpl();

        final List<Integer> createExpirySecondsCalls = new CopyOnWriteArrayList<>();
        final List<Integer> createEphemeralExpirySecondsCalls = new CopyOnWriteArrayList<>();
        final List<CryptoProvider> createdProviders = new CopyOnWriteArrayList<>();
        final List<Integer> maxRefreshFailuresCalls = new CopyOnWriteArrayList<>();
        /** A copy of each wrapped payload createAsync received (the provider zeroes the original on close). */
        final List<byte[]> createdWrapped = new CopyOnWriteArrayList<>();

        @Override
        public CompletableFuture<CryptoProvider> createAsync(KeyWrapper wrapper, byte[] wrapped, int expirySeconds, Integer maxRefreshFailures) {
            createExpirySecondsCalls.add(expirySeconds);
            maxRefreshFailuresCalls.add(maxRefreshFailures);
            createdWrapped.add(wrapped.clone());
            return inner.createAsync(wrapper, wrapped, expirySeconds, maxRefreshFailures).thenApply(this::record);
        }

        @Override
        public CompletableFuture<CryptoProvider> createEphemeralAsync(KeyWrapper wrapper, int expirySeconds, Integer maxRefreshFailures) {
            createEphemeralExpirySecondsCalls.add(expirySeconds);
            maxRefreshFailuresCalls.add(maxRefreshFailures);
            return inner.createEphemeralAsync(wrapper, expirySeconds, maxRefreshFailures).thenApply(this::record);
        }

        private CryptoProvider record(CryptoProvider provider) {
            createdProviders.add(provider);
            return provider;
        }
    }

    /** A key that does nothing, records whether it was closed, and can fail to close. */
    static final class TrackingKey implements DataEncryptionKey, AutoCloseable {
        volatile boolean closed;
        final boolean throwOnClose;

        TrackingKey() {
            this(false);
        }

        TrackingKey(boolean throwOnClose) {
            this.throwOnClose = throwOnClose;
        }

        @Override
        public byte[] encrypt(byte[] plaintext) {
            return new byte[0];
        }

        @Override
        public byte[] encrypt(byte[] plaintext, byte[] aad) {
            return new byte[0];
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] result) {
            return 0;
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
            return 0;
        }

        @Override
        public void close() {
            closed = true;
            if (throwOnClose)
                throw new IllegalStateException("close failed");
        }
    }

    /** A key with no close at all. */
    static final class NonClosableKey implements DataEncryptionKey {
        @Override
        public byte[] encrypt(byte[] plaintext) {
            return new byte[0];
        }

        @Override
        public byte[] encrypt(byte[] plaintext, byte[] aad) {
            return new byte[0];
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] result) {
            return 0;
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
            return 0;
        }
    }
}
