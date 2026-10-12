package io.github.runsecure.hkdfguard.abstractions;

/** Size limits for a wrapped DEK - the bytes a key file holds and a {@link KeyWrapper} produces. */
public final class WrappedKeyLimits {
    /**
     * Largest wrapped DEK, in bytes, this library will read from a key file or let a key wrapper
     * generate. Today's native payloads are far smaller (156 bytes on macOS); the headroom allows
     * larger keys for other symmetric algorithms and additional fingerprinting.
     */
    public static final int MAX_BYTES = 512;

    private WrappedKeyLimits() {
    }
}
