package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.util.Objects;

/**
 * Base class for tokens that identify configuration items delimited by a start and end sequence,
 * such as {@code ${Name}}.
 */
public abstract class ConfigurationItemTokenBase {
    /** The default sequence that marks the start of a configuration item. */
    public static final String DEFAULT_START_SEQUENCE = "${";

    /** The default sequence that marks the end of a configuration item. */
    public static final String DEFAULT_END_SEQUENCE = "}";

    /**
     * The escape sequence used by {@link DefaultToken}, so that {@code $${Name}} is written as the
     * literal text {@code ${Name}}.
     */
    public static final String DEFAULT_ESCAPE_SEQUENCE = "$";

    private final String startSequence;
    private final String endSequence;
    private final String escapeSequence;

    /** The default start and end sequences, with no escape sequence. */
    protected ConfigurationItemTokenBase() {
        this(DEFAULT_START_SEQUENCE, DEFAULT_END_SEQUENCE, null);
    }

    /**
     * Custom sequences.
     *
     * @param startSequence  the sequence that marks the start of a configuration item
     * @param endSequence    the sequence that marks the end of a configuration item
     * @param escapeSequence the sequence that, directly before a start sequence, makes it literal
     *                       text instead of the start of an item; or null for no escape sequence
     * @throws NullPointerException     startSequence or endSequence is null
     * @throws IllegalArgumentException startSequence, endSequence or escapeSequence is empty
     */
    protected ConfigurationItemTokenBase(String startSequence, String endSequence, String escapeSequence) {
        Objects.requireNonNull(startSequence, "startSequence");
        Objects.requireNonNull(endSequence, "endSequence");
        if (startSequence.isEmpty())
            throw new IllegalArgumentException("startSequence cannot be empty.");
        if (endSequence.isEmpty())
            throw new IllegalArgumentException("endSequence cannot be empty.");
        if (escapeSequence != null && escapeSequence.isEmpty())
            throw new IllegalArgumentException("escapeSequence cannot be empty.");

        this.startSequence = startSequence;
        this.endSequence = endSequence;
        this.escapeSequence = escapeSequence;
    }

    /**
     * Gets the sequence that marks the start of a configuration item.
     *
     * @return the start sequence
     */
    public final String getStartSequence() {
        return startSequence;
    }

    /**
     * Gets the sequence that marks the end of a configuration item.
     *
     * @return the end sequence
     */
    public final String getEndSequence() {
        return endSequence;
    }

    /**
     * Gets the sequence that, directly before a start sequence, makes it literal text.
     * <p>
     * The escape sequence is removed and the start sequence is copied as text, so with the escape
     * sequence {@code $}, {@code $${Name}} is written as {@code ${Name}} and {@code Name} is not a
     * key. Only the start sequence is escaped: the text after it is read as usual, so it can contain
     * other items. An escape sequence anywhere else is ordinary text.
     *
     * @return the escape sequence, or null if the token has none
     */
    public final String getEscapeSequence() {
        return escapeSequence;
    }
}
