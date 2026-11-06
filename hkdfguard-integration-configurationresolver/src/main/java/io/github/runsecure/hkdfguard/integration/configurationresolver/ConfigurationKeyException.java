package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.util.Objects;
import java.util.OptionalInt;

/**
 * The exception thrown when the value for a configuration key could not be resolved.
 * <p>
 * The message contains only the item's position and the {@link #getError() error}, so it is safe to
 * log. The key is available from {@link #getKey()}; it may come from the source text, which may be
 * untrusted, so treat it as untrusted input before logging or displaying it.
 */
public final class ConfigurationKeyException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String key;
    private final ConfigurationKeyError error;
    private final Integer sourceIndex;

    /**
     * For a key whose position in a source is not known, such as when thrown by a value provider.
     *
     * @param key   the configuration key
     * @param error why the value could not be resolved
     */
    public ConfigurationKeyException(String key, ConfigurationKeyError error) {
        super("The value for a configuration key could not be resolved (" + Objects.requireNonNull(error, "error") + ").");
        this.key = key;
        this.error = error;
        this.sourceIndex = null;
    }

    /**
     * For a configuration item in a source.
     *
     * @param key         the trimmed key of the configuration item
     * @param error       why the item could not be resolved
     * @param sourceIndex the index in the source where the item's start sequence begins
     * @param cause       the exception that caused this one, or null
     */
    public ConfigurationKeyException(String key, ConfigurationKeyError error, int sourceIndex, Throwable cause) {
        super("The configuration item at index " + sourceIndex + " could not be resolved (" + Objects.requireNonNull(error, "error") + ").", cause);
        this.key = key;
        this.error = error;
        this.sourceIndex = sourceIndex;
    }

    /**
     * For a configuration item in a source.
     *
     * @param key         the trimmed key of the configuration item
     * @param error       why the item could not be resolved
     * @param sourceIndex the index in the source where the item's start sequence begins
     */
    public ConfigurationKeyException(String key, ConfigurationKeyError error, int sourceIndex) {
        this(key, error, sourceIndex, null);
    }

    /**
     * Gets the configuration key. When thrown by a resolver it comes from the source text and may be
     * untrusted.
     *
     * @return the key
     */
    public String getKey() {
        return key;
    }

    /**
     * Gets why the value could not be resolved.
     *
     * @return the error
     */
    public ConfigurationKeyError getError() {
        return error;
    }

    /**
     * Gets the index in the source where the item's start sequence begins: a character index when
     * resolving characters, or a byte index when resolving UTF-8 bytes, counted from the source's
     * position.
     *
     * @return the index, or empty when the exception was thrown outside a resolver, such as by a value
     *         provider called directly
     */
    public OptionalInt getSourceIndex() {
        return sourceIndex == null ? OptionalInt.empty() : OptionalInt.of(sourceIndex);
    }
}
