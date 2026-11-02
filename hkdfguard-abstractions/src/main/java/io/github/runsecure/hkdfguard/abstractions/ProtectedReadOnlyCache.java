package io.github.runsecure.hkdfguard.abstractions;

import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;

/**
 * Read surface of a highly concurrent name -&gt; encrypted-value cache. Names are compared ignoring
 * ASCII case only ("Item" and "ITEM" are the same name; "café" and "CAFÉ" are not), and each value
 * is bound to its name, so a value can only be revealed under the name it was stored for. Decrypt
 * reveals a stored value into a caller-owned buffer, returning 0 for a missing name rather than
 * throwing. Nothing here ever holds plaintext beyond the duration of a single decrypt call.
 * <p>
 * A cache that may have to fetch a value over the network on a miss (a remote secret store) does
 * that I/O asynchronously in {@link #decryptAsync(String, byte[])},
 * {@link #decryptAsync(String, char[])} and {@link #findMaxDecryptedLengthAsync}, where the
 * synchronous members block the calling thread until it completes. Their default implementations
 * call the synchronous members, which is all an in-memory cache needs. Failures complete the
 * returned future exceptionally, never throw; cancelling it stops waiting for a fetch. Zero result
 * once the value is used, as with any buffer holding plaintext.
 */
public interface ProtectedReadOnlyCache {
    /**
     * Decrypts the value stored under name into result.
     *
     * @return the number of bytes written to result, or 0 if no value is stored under name
     */
    int decrypt(String name, byte[] result);

    /**
     * Decrypts the value stored under name into result as UTF-8-decoded characters.
     *
     * @return the number of chars written to result, or 0 if no value is stored under name
     */
    int decrypt(String name, char[] result);

    /**
     * An upper bound on how many bytes or chars decrypt will write for the value stored under
     * name, so a result buffer can be sized without decrypting first; empty if no value is stored
     * under name.
     */
    OptionalInt findMaxDecryptedLength(String name);

    /**
     * Decrypts the value stored under name into result, as {@link #decrypt(String, byte[])} does,
     * fetching it asynchronously first if the cache must.
     *
     * @return completes with the number of bytes written to result, or 0 if no value is stored
     *         under name
     */
    default CompletableFuture<Integer> decryptAsync(String name, byte[] result) {
        try {
            return CompletableFuture.completedFuture(decrypt(name, result));
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Decrypts the value stored under name into result as UTF-8-decoded characters, as
     * {@link #decrypt(String, char[])} does, fetching it asynchronously first if the cache must.
     *
     * @return completes with the number of chars written to result, or 0 if no value is stored
     *         under name
     */
    default CompletableFuture<Integer> decryptAsync(String name, char[] result) {
        try {
            return CompletableFuture.completedFuture(decrypt(name, result));
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * {@link #findMaxDecryptedLength}, fetching the value asynchronously first if the cache must.
     *
     * @return completes with the upper bound, or empty if no value is stored under name
     */
    default CompletableFuture<OptionalInt> findMaxDecryptedLengthAsync(String name) {
        try {
            return CompletableFuture.completedFuture(findMaxDecryptedLength(name));
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }
}
