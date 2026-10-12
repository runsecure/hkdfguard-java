package io.github.runsecure.hkdfguard.abstractions;

import java.nio.CharBuffer;

/**
 * A short-lived, string-level protector for a pipeline that must encrypt secrets before a durable
 * KEK exists. Unlike {@link DataProtector}, it is not bound to one purpose: every encrypt/decrypt
 * names the secret it's protecting, so one instance - and therefore one key - can protect many
 * secrets, each bound to its own identifier. It owns a single in-memory key for its whole
 * lifetime, stamps every value with {@link #getKeyVersion()}, and exposes that key once the
 * pipeline is done so it can be wrapped under a real KEK.
 * <p>
 * The secret identifier is the configuration key the value will be stored under - its full path,
 * e.g. "ConnectionStrings:Admin". It's bound into the value as Additional Authenticated Data via
 * {@link ProtectedConfigurationPurpose}, the same rule the configuration reader uses, so once this
 * key is wrapped and registered at {@link #getKeyVersion()}, reading that configuration key reveals
 * the value - and a value copied under any other key fails authentication. Identifiers are
 * case-insensitive for ASCII letters only.
 */
public interface PipelineDataProtector extends AutoCloseable {
    /** The version stamped on every value - the version this key will be registered under. */
    int getKeyVersion();

    /**
     * Encrypts plaintext bound to {@code secretIdentifier}, and formats the result via the
     * configured {@link EncryptedFormatProvider}.
     *
     * @param plaintext        the secret to protect; read-only, so it is not zeroed (its UTF-8 copy
     *                         inside this call is)
     * @param secretIdentifier the configuration key the value will be stored under; decrypt must
     *                         name the same secret
     * @return the formatted, encrypted string
     * @throws IllegalArgumentException secretIdentifier is empty or not valid UTF-16
     */
    String encrypt(CharSequence plaintext, CharSequence secretIdentifier);

    /**
     * Parses and decrypts a formatted value directly into result, verifying it was encrypted for
     * {@code secretIdentifier} - never materializes the plaintext as a String.
     *
     * @return the number of chars written to result
     * @throws IllegalArgumentException secretIdentifier is empty or not valid UTF-16
     */
    int decrypt(CharSequence encrypted, CharSequence secretIdentifier, char[] result);

    /** An upper bound on how many chars decrypt will write for the given formatted value. */
    int getMaxDecryptedLength(CharSequence encrypted);

    /**
     * The key, base64-encoded, for handing to the native platform's wrap process at the end of the
     * pipeline. A read-only view of a buffer the protector owns and zeroes on close: consume it
     * before closing, and never copy it into a String. Pass it to the wrap tool on standard input
     * ({@code --dek-stdin}), never as a command-line argument or environment variable, which
     * process listings and logs capture.
     */
    CharBuffer getKeyAsBase64();

    /** Zeroes the key and its base64 form. Safe to call more than once. */
    @Override
    void close();
}
