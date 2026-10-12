package io.github.runsecure.hkdfguard.abstractions;

import java.io.Serial;

/**
 * AEAD decryption failed authentication: the ciphertext was altered, was encrypted under another
 * key, or is being decrypted with different Additional Authenticated Data than it was encrypted
 * with (e.g. under another name or configuration key). No plaintext is ever returned.
 */
public class AuthenticationTagMismatchException extends CryptographicException {
    @Serial
    private static final long serialVersionUID = 1L;

    public AuthenticationTagMismatchException() {
        super("The computed authentication tag did not match the input authentication tag.");
    }

    public AuthenticationTagMismatchException(Throwable cause) {
        super("The computed authentication tag did not match the input authentication tag.", cause);
    }
}
