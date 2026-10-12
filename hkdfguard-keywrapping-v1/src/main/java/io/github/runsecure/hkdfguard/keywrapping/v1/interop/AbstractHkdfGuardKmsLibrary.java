package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

/**
 * Shared surface over a platform's native HkdfGuard KMS library. Every implementation wraps and
 * unwraps a fixed-length DEK under a persistent, per-service KEK held outside the JVM (a TPM2 key,
 * a Secure Enclave key, etc.) via that platform's hkdfguard_wrap_dek / hkdfguard_unwrap_dek /
 * hkdfguard_generate_and_wrap_dek native functions - identical in shape across platforms, but each
 * library's negative status codes mean different things, so callers must consult the concrete
 * implementation they're using to interpret a non-{@link #OK} result.
 * <p>
 * Internal to the KeyWrapping module: this package is not exported.
 */
public abstract class AbstractHkdfGuardKmsLibrary {
    public static final int DEK_LENGTH = 32;

    /** Status code common to every platform's native library: the call succeeded. */
    public static final int OK = 0;

    protected AbstractHkdfGuardKmsLibrary() {
    }

    /**
     * What a non-{@link #OK} status means on this platform, for error messages - or null when the
     * code is unknown. Status codes differ between platforms, so only the platform's own binding
     * can say.
     */
    public String describeStatus(int status) {
        return null;
    }

    /**
     * Wraps {@code dek} under the persistent KEK identified by {@code service}.
     *
     * @param service     non-empty, cross-platform identity of the KEK
     * @param dek         the plaintext DEK to wrap (must be exactly {@link #DEK_LENGTH} bytes)
     * @param destination receives the wrapped payload
     * @return {@link #OK} and the number of bytes written; or a negative, implementation-specific
     *         status - with, on a buffer-too-small failure, the required capacity
     */
    public abstract KmsResult wrapDek(String service, byte[] dek, byte[] destination);

    /**
     * Unwraps a payload previously produced by {@link #wrapDek} for the same {@code service},
     * recovering the original DEK.
     *
     * @return {@link #OK} and {@link #DEK_LENGTH}; or a negative, implementation-specific status
     */
    public abstract KmsResult unwrapDek(String service, byte[] wrapped, byte[] destination);

    /**
     * Generates a fresh, cryptographically random DEK and immediately wraps it under the persistent
     * KEK identified by {@code service}. The plaintext DEK never crosses this boundary - recover it
     * later via {@link #unwrapDek} with the same {@code service}.
     *
     * @return {@link #OK} and the number of bytes written; or a negative, implementation-specific status
     */
    public abstract KmsResult generateAndWrapDek(String service, byte[] destination);
}
