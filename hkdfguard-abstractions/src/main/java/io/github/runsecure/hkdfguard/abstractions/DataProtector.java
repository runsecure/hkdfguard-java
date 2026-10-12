package io.github.runsecure.hkdfguard.abstractions;

/**
 * A named, string-level data protector: the name given at construction is used as the Additional
 * Authenticated Data for every encrypt/decrypt, binding a protected value to the purpose it was
 * protected for so it can't be reused under a different one. Encrypt/decrypt resolve the actual
 * {@link DataEncryptionKey} to use from a {@link KeyRing}, rather than holding one key permanently.
 */
public interface DataProtector {
    /**
     * Encrypts a plaintext string and formats the result via the configured
     * {@link EncryptedFormatProvider}.
     *
     * @param plaintext the plaintext to encrypt; read-only, so it is not zeroed: the caller owns it
     *                  and should clear it once done (its UTF-8 copy inside this call is zeroed).
     *                  Pass a {@code CharBuffer.wrap(char[])} to keep a secret out of String.
     * @return the formatted, encrypted string
     */
    String encrypt(CharSequence plaintext);

    /**
     * Parses a formatted encrypted string and decrypts it directly into {@code result} - this
     * never materializes the plaintext as a String.
     *
     * @param encrypted the formatted, encrypted string
     * @param result    receives the decrypted plaintext characters
     * @return the number of chars written to result
     */
    int decrypt(CharSequence encrypted, char[] result);

    /**
     * An upper bound on how many chars decrypt will write for the given formatted string, so a
     * result buffer can be sized without decrypting first.
     */
    int getMaxDecryptedLength(CharSequence encrypted);
}
