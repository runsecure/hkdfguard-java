package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.io.Serial;

/**
 * A response Vault returned isn't the JSON a {@link VaultClient} method reads: malformed, or a
 * value of another type where a model expects an object, a number or a date-time. Its message
 * never quotes the response, which may hold a secret.
 */
public final class VaultJsonException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;

    public VaultJsonException(String message) {
        super(message);
    }
}
