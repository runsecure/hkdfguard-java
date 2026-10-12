package io.github.runsecure.hkdfguard.abstractions;

/**
 * The refresh-failure policy's shared default. A provider re-reveals its key through the KEK on a
 * schedule; after this many consecutive failed attempts it fails closed - zeroes the key and
 * refuses every operation until a refresh succeeds - so revoking the KEK reaches a running
 * process. Everything that takes a {@code maxRefreshFailures} defaults to this; passing null
 * explicitly opts into failing open.
 */
public final class RefreshFailurePolicy {
    /** Consecutive failed refreshes tolerated before failing closed, unless configured otherwise. */
    public static final int DEFAULT_MAX_REFRESH_FAILURES = 3;

    private RefreshFailurePolicy() {
    }
}
