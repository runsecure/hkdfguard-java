package io.github.runsecure.hkdfguard.abstractions;

/** Formats an encrypted value and its key version into the stored string, and parses it back. */
public interface EncryptedFormatProvider {
    /** Formats {@code value} into its stored form. */
    String format(KeyTrackingValue value);

    /**
     * Parses a stored value.
     *
     * @throws EncryptedFormatException encrypted is malformed
     */
    KeyTrackingValue parse(CharSequence encrypted);

    /**
     * Computes an upper bound on the decrypted plaintext's length (bytes or chars - safe for
     * either, since the UTF-8-decoded char count never exceeds the byte count) from the payload's
     * length alone, without decoding it. AEAD ciphertext is always at least as long as the
     * plaintext it encloses, so the actual decrypted length is this value or less.
     *
     * @throws EncryptedFormatException encrypted is malformed
     */
    int getMaxDecryptedLength(CharSequence encrypted);
}
