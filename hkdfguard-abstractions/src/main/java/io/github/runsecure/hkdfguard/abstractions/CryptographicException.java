package io.github.runsecure.hkdfguard.abstractions;

import java.io.Serial;

/**
 * A cryptographic operation failed: a key wrapper could not reveal a key, a key is suspended or
 * over its encryption limit, or a native KMS call returned an error. Unchecked, like every other
 * HkdfGuard exception, so it passes through lambdas and CompletableFuture stages unchanged.
 */
public class CryptographicException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;

    public CryptographicException(String message) {
        super(message);
    }

    public CryptographicException(String message, Throwable cause) {
        super(message, cause);
    }
}
