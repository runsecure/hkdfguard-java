package io.github.runsecure.hkdfguard.cache.hashicorpvault;

import java.io.Serial;

/**
 * Vault answered a read with a status other than success or "nothing at this path": 403 for a token
 * that is invalid or not allowed to read the path, a 404 naming an error (no such mount), 503 while
 * Vault is sealed, a redirect, and so on. The counterpart of the HttpRequestException .NET's cache
 * throws. Its message holds the path read, the status and the errors Vault listed, never the token.
 * Unchecked, like every other HkdfGuard exception, so it passes through a fetch unchanged.
 */
public class VaultRequestException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;

    private final int statusCode;

    public VaultRequestException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    /** The HTTP status Vault answered with. */
    public int statusCode() {
        return statusCode;
    }

    /**
     * Whether another attempt may be answered differently: 429 (rate limited) or a 5xx other than
     * 501 (Vault answers 503 while sealed or electing a leader).
     */
    public boolean isTransient() {
        return statusCode == 429 || (statusCode >= 500 && statusCode != 501);
    }
}
