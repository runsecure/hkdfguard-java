package io.github.runsecure.hkdfguard.cache;

import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.ProtectedCacheBase;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.DataEncryptionKeyImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;

/** Real key rings of real AES-256-GCM keys for the caches to resolve from, and test doubles. */
final class TestRings {
    private static final SecureRandom RANDOM = new SecureRandom();

    private TestRings() {
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static String text(byte[] bytes, int length) {
        return new String(bytes, 0, length, StandardCharsets.UTF_8);
    }

    /** A real key over a fixed random DEK. */
    static DataEncryptionKey newKey() {
        var key = new byte[32];
        RANDOM.nextBytes(key);
        return new DataEncryptionKeyImpl(Futures.await(AesGcmCryptoProviderImpl.createAsync(new FixedKeyWrapper(key), utf8("wrapped"), 60)));
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
            throw new UnsupportedOperationException();
        }
    }

    /**
     * A minimal ProtectedCacheBase subclass whose tryPopulate is driven directly by the test, with
     * ways to tamper with its entries as a populate bug or an attacker would.
     */
    static final class PopulatingCache extends ProtectedCacheBase {
        int tryPopulateCallCount;
        Predicate<String> onTryPopulate;

        PopulatingCache(KeyRing ring) {
            super(ring);
        }

        void seed(String name, char[] plaintext) {
            putEntry(name, encryptChars(name, plaintext));
        }

        /** Copies one entry's ciphertext under another name. */
        void copyEntry(String from, String to) {
            putEntry(to, getEntry(from));
        }

        int versionOf(String name) {
            return getEntry(name).keyVersion();
        }

        /** Rewrites an entry's recorded key version. */
        void relabelVersion(String name, int version) {
            putEntry(name, new KeyTrackingValue(version, getEntry(name).value()));
        }

        @Override
        protected boolean tryPopulate(String name) {
            tryPopulateCallCount++;
            return onTryPopulate != null && onTryPopulate.test(name);
        }
    }

    /** A read-only cache whose every member throws. */
    static final class ThrowingReadOnlyCache implements ProtectedReadOnlyCache {
        private final RuntimeException exception;

        ThrowingReadOnlyCache(RuntimeException exception) {
            this.exception = exception;
        }

        @Override
        public int decrypt(String name, byte[] result) {
            throw exception;
        }

        @Override
        public int decrypt(String name, char[] result) {
            throw exception;
        }

        @Override
        public OptionalInt findMaxDecryptedLength(String name) {
            throw exception;
        }
    }
}
