package io.github.runsecure.hkdfguard.abstractions;

import java.io.Serial;

/**
 * A key has performed as many encryptions as its cipher safely allows; rotate it. Decryption still
 * works. Thrown by encrypt when a key reaches its AES-GCM encryption budget, or when a key file has
 * passed its maximum age (see {@code KeyRingBuilder.withKeyFileMaxAgeDays}).
 */
public class EncryptionLimitReachedException extends CryptographicException {
    @Serial
    private static final long serialVersionUID = 1L;

    /** @param message which key reached its limit, and what to do about it */
    public EncryptionLimitReachedException(String message) {
        super(message);
    }
}
