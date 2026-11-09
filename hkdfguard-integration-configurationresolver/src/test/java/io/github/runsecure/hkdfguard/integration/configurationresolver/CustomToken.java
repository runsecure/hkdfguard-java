package io.github.runsecure.hkdfguard.integration.configurationresolver;

/** A token with custom start, end, and escape sequences. */
final class CustomToken extends ConfigurationItemTokenBase {
    CustomToken(String startSequence, String endSequence) {
        this(startSequence, endSequence, null);
    }

    CustomToken(String startSequence, String endSequence, String escapeSequence) {
        super(startSequence, endSequence, escapeSequence);
    }
}
