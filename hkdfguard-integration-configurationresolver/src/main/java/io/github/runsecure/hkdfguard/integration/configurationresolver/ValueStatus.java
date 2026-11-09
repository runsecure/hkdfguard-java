package io.github.runsecure.hkdfguard.integration.configurationresolver;

/** The result of asking a {@link ValueProvider} for a value. */
public enum ValueStatus {
    /** The key was found and its value was written. */
    FOUND,

    /** The key was not found. Nothing was written. */
    NOT_FOUND,

    /** The key was found, but its value does not fit in the destination. Nothing usable was written. */
    DESTINATION_TOO_SMALL,
}
