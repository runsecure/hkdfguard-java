package io.github.runsecure.hkdfguard.integration.configurationresolver;

/**
 * A token that uses the default <code>$&#123;</code> and <code>&#125;</code> sequences, with {@code $} as its
 * escape sequence, so {@code $${Name}} is written as the literal text {@code ${Name}}.
 */
public final class DefaultToken extends ConfigurationItemTokenBase {
    /** Creates the token. */
    public DefaultToken() {
        super(DEFAULT_START_SEQUENCE, DEFAULT_END_SEQUENCE, DEFAULT_ESCAPE_SEQUENCE);
    }
}
