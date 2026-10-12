package io.github.runsecure.hkdfguard.abstractions;

import java.util.concurrent.CompletableFuture;

/**
 * Protects ({@link #wrapAsync}) and reveals ({@link #unwrapAsync}) an encryption key against a
 * single, implicitly identified KEK (e.g. a native KMS-backed key, identified by service name at
 * construction, or a remote KMS/HSM key). unwrapAsync takes the wrapped payload as an explicit
 * argument on every call, so one instance can reveal any number of different wrapped keys sharing
 * the same KEK - it holds no wrapped payload of its own. Asynchronous so that network-backed KEKs
 * (e.g. AWS KMS, CloudHSM) are never blocked on; local implementations may return an already
 * completed future.
 * <p>
 * Failures should be reported by completing the returned future exceptionally; callers also treat
 * an exception thrown by the call itself as a failure.
 */
public interface KeyWrapper {
    /**
     * Protects an encryption key.
     *
     * @param plaintext the plaintext key to protect
     * @param result    receives the wrapped key
     * @return completes with the number of bytes written to result
     */
    CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result);

    /**
     * Reveals a previously wrapped key. Implementations must write the complete key and report its
     * exact length - consumers reject any other count rather than use a partially filled buffer -
     * must fail (never return unauthenticated bytes) when {@code wrapped} has been tampered with,
     * and should zero {@code result} on failure.
     *
     * @param wrapped the wrapped key to reveal
     * @param result  receives the plaintext key
     * @return completes with the number of bytes written to result
     */
    CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result);

    /**
     * Generates a fresh key and immediately protects it against the same KEK this instance wraps
     * and reveals against - the plaintext key never crosses this call.
     *
     * @param result receives the wrapped key
     * @return completes with the number of bytes written to result
     */
    CompletableFuture<Integer> generateAndWrapAsync(byte[] result);
}
