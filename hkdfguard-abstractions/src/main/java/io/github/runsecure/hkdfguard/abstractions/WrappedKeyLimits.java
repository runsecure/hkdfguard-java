package io.github.runsecure.hkdfguard.abstractions;

/** Size limits for a wrapped DEK - the bytes a key file holds and a {@link KeyWrapper} produces. */
public final class WrappedKeyLimits {
    /**
     * Largest wrapped DEK, in bytes, this library will read from a key file or let a key wrapper
     * generate. Today's native payloads are far smaller (Windows 132, Linux 276, macOS 125 bytes),
     * so one buffer of this size holds any platform's wrapped DEK; the headroom allows
     * larger keys for other symmetric algorithms and additional fingerprinting.
     */
    public static final int MAX_BYTES = 512;

    private WrappedKeyLimits() {
    }
}
