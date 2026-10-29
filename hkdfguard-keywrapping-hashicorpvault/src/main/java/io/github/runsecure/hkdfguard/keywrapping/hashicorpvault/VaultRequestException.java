package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import java.io.Serial;

/**
 * Vault answered a transit request with a status other than success: 400 for a ciphertext that
 * doesn't authenticate (tampered with, or wrapped under another key or context) or whose key
 * version is below min_decryption_version, 403 for a token that is invalid or not allowed to use
 * the key, 503 while Vault is sealed, a redirect, and so on. The cause of the
 * {@link io.github.runsecure.hkdfguard.abstractions.CryptographicException} a wrapper's future
 * fails with - the counterpart of the HttpRequestException .NET's wrapper puts there. Its message
 * holds the status and the errors Vault listed, never the token or a key.
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
