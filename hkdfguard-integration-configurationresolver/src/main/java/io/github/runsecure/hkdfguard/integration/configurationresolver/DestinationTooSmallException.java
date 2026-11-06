package io.github.runsecure.hkdfguard.integration.configurationresolver;

/**
 * The exception thrown when a resolver's destination is too small for the resolved text. .NET throws
 * an {@code ArgumentException} for the {@code destination} parameter; Java has no parameter name to
 * tell it apart, so it has a type of its own, and a caller can catch it to retry with more room.
 */
public final class DestinationTooSmallException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    /** Creates the exception, with a fixed message. */
    public DestinationTooSmallException() {
        super("The destination is too small for the resolved text.");
    }
}
