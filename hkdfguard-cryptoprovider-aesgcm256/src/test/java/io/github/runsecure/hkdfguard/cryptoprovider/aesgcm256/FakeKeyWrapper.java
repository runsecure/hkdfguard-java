package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A KeyWrapper that reveals a fresh random key (or a fixed one), counting calls - isolates provider
 * tests from any real native KMS machinery. Thread-safe: the provider unwraps from its background
 * refresh thread while the test thread reconfigures it.
 */
class FakeKeyWrapper implements KeyWrapper {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final AtomicInteger unwrapCallCount = new AtomicInteger();
    private final AtomicInteger generateAndWrapCallCount = new AtomicInteger();
    private final byte[] fixedKey;

    /** When set, unwrapAsync throws this (synchronously) instead of revealing a key. */
    volatile RuntimeException throwOnUnwrap;

    /**
     * When set, unwrapAsync fills only this many bytes and reports that count - models a wrapper
     * backed by a key of the wrong size (e.g. a KMS data key generated as AES-128).
     */
    volatile Integer unwrapBytesWrittenOverride;

    FakeKeyWrapper() {
        this(null);
    }

    /**
     * @param fixedKey revealed on every unwrap (as a real wrapper does for one wrapped payload)
     *                 instead of a fresh random key - needed by any test that decrypts across a
     *                 background refresh
     */
    FakeKeyWrapper(byte[] fixedKey) {
        this.fixedKey = fixedKey;
    }

    static byte[] randomKey() {
        var key = new byte[32];
        RANDOM.nextBytes(key);
        return key;
    }

    int unwrapCallCount() {
        return unwrapCallCount.get();
    }

    int generateAndWrapCallCount() {
        return generateAndWrapCallCount.get();
    }

    @Override
    public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
        throw new UnsupportedOperationException();
    }

    @Override
    public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
        unwrapCallCount.incrementAndGet();
        var failure = throwOnUnwrap;
        if (failure != null)
            throw failure;

        var override = unwrapBytesWrittenOverride;
        var written = override != null ? override : result.length;
        var filled = Math.min(written, result.length);
        if (fixedKey == null) {
            var random = new byte[filled];
            RANDOM.nextBytes(random);
            System.arraycopy(random, 0, result, 0, filled);
        } else {
            System.arraycopy(fixedKey, 0, result, 0, filled);
        }
        return CompletableFuture.completedFuture(written);
    }

    @Override
    public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
        generateAndWrapCallCount.incrementAndGet();
        Arrays.fill(result, 0, 32, (byte) 7);
        return CompletableFuture.completedFuture(32);
    }
}
