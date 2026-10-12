package io.github.runsecure.hkdfguard.abstractions;

import java.util.concurrent.CompletableFuture;

/**
 * Owns one revealed DEK - how it is revealed, refreshed and eventually zeroed - and performs the
 * AEAD encrypt/decrypt with it.
 * <p>
 * <b>Implementations must zero {@code plaintext} in every encrypt</b>, before returning and on every
 * failure path - including when the key is unavailable (suspended or closed) and the call throws
 * before any encryption happens. {@link DataEncryptionKey} promises its callers exactly this and
 * relies on the provider to keep it. Decrypt never modifies its ciphertext.
 */
public interface CryptoProvider extends AutoCloseable {
    /**
     * Encrypts plaintext under this provider's key.
     *
     * @param plaintext the bytes to protect; zeroed before this returns or throws
     * @param result    receives the encrypted data; at least {@link #getEncryptedAllocationLength} long
     * @return the number of bytes written to result
     */
    int encrypt(byte[] plaintext, byte[] result);

    /**
     * Encrypts plaintext under this provider's key, bound to {@code aad}.
     *
     * @param plaintext the bytes to protect; zeroed before this returns or throws
     * @param aad       the Additional Authenticated Data; decrypt must supply the same bytes
     * @param result    receives the encrypted data; at least {@link #getEncryptedAllocationLength} long
     * @return the number of bytes written to result
     */
    int encrypt(byte[] plaintext, byte[] aad, byte[] result);

    /**
     * Decrypts and authenticates ciphertext.
     *
     * @param ciphertext the complete encrypted value
     * @param result     receives the plaintext
     * @return the number of bytes written to result
     */
    int decrypt(byte[] ciphertext, byte[] result);

    /**
     * Decrypts and authenticates ciphertext encrypted with {@code aad}.
     *
     * @param ciphertext the complete encrypted value
     * @param aad        the Additional Authenticated Data it was encrypted with
     * @param result     receives the plaintext
     * @return the number of bytes written to result
     */
    int decrypt(byte[] ciphertext, byte[] aad, byte[] result);

    /** The buffer length encrypt needs for a plaintext of {@code length} bytes. */
    int getEncryptedAllocationLength(int length);

    /** The buffer length decrypt needs for a ciphertext of {@code length} bytes; never negative. */
    int getDecryptedAllocationLength(int length);

    /**
     * Closes this provider without blocking the caller: completes once any background work has
     * stopped and every revealed key has been zeroed. Safe to call more than once.
     */
    CompletableFuture<Void> closeAsync();

    /** Closes this provider, blocking until background work has stopped. Safe to call more than once. */
    @Override
    void close();
}
