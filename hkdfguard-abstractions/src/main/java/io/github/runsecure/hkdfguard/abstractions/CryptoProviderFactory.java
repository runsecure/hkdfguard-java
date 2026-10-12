package io.github.runsecure.hkdfguard.abstractions;

import java.util.concurrent.CompletableFuture;

/**
 * Mints {@link CryptoProvider}s for a key ring. Creation is asynchronous because building a
 * provider reveals its first key through the {@link KeyWrapper}, which for a network-backed key
 * wrapper is a remote call. Every provider then refreshes its revealed key every
 * {@code expirySeconds}; {@code maxRefreshFailures} is the refresh-failure policy: a value makes the
 * provider fail closed - close its key and refuse every operation - once that many consecutive
 * refreshes have failed, until one succeeds again, while null keeps serving on the last good key
 * no matter how many refreshes fail (fail open). The overloads without it fail closed after
 * {@link RefreshFailurePolicy#DEFAULT_MAX_REFRESH_FAILURES} failures.
 * <p>
 * Invalid arguments are rejected with an exception thrown by the call itself, before any key
 * wrapper call; failures revealing the key complete the returned future exceptionally.
 */
public interface CryptoProviderFactory {
    /**
     * @param wrapper            reveals the DEK
     * @param wrapped            the wrapped DEK payload (e.g. a key file's bytes); owned by the
     *                           provider from here on, and zeroed when it's closed
     * @param expirySeconds      session lifetime and background refresh interval, 1-300
     * @param maxRefreshFailures consecutive failed refreshes tolerated before failing closed, at
     *                           least 1; null to fail open
     * @throws IllegalArgumentException expirySeconds or maxRefreshFailures is out of range
     */
    CompletableFuture<CryptoProvider> createAsync(KeyWrapper wrapper, byte[] wrapped, int expirySeconds, Integer maxRefreshFailures);

    /** {@link #createAsync(KeyWrapper, byte[], int, Integer)}, failing closed by default. */
    default CompletableFuture<CryptoProvider> createAsync(KeyWrapper wrapper, byte[] wrapped, int expirySeconds) {
        return createAsync(wrapper, wrapped, expirySeconds, RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES);
    }

    /**
     * @param wrapper            generates and wraps a fresh DEK ({@link KeyWrapper#generateAndWrapAsync}), then reveals it
     * @param expirySeconds      session lifetime and background refresh interval, 1-300
     * @param maxRefreshFailures see {@link #createAsync(KeyWrapper, byte[], int, Integer)}
     * @throws IllegalArgumentException expirySeconds or maxRefreshFailures is out of range
     */
    CompletableFuture<CryptoProvider> createEphemeralAsync(KeyWrapper wrapper, int expirySeconds, Integer maxRefreshFailures);

    /** {@link #createEphemeralAsync(KeyWrapper, int, Integer)}, failing closed by default. */
    default CompletableFuture<CryptoProvider> createEphemeralAsync(KeyWrapper wrapper, int expirySeconds) {
        return createEphemeralAsync(wrapper, expirySeconds, RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES);
    }
}
