package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.io.Serial;

/**
 * Vault answered a request with a status other than success: 400 for a request it refused, 403 for
 * a token that is invalid or not allowed the path, 503 while Vault is sealed, a redirect, and so
 * on. The counterpart of the HttpRequestException (with a status) .NET's Vault code throws: what
 * the transit key wrapper puts as the cause of the CryptographicException it fails with, what the
 * secret cache throws, and the base of {@link VaultClient}'s {@link VaultResponseException} and
 * {@link VaultRedirectException}. Its message holds the status and the errors Vault listed, never
 * a token, key or secret. Unchecked, like every other HkdfGuard exception.
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
        return VaultHttp.isTransientStatus(statusCode);
    }
}
