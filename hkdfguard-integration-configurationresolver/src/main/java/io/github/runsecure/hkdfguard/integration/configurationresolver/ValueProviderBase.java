package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * Base class for value providers whose values are bytes, such as files or decrypted data.
 * <p>
 * Derived classes implement {@link #tryGetBytes} and {@link #findByteCount}. The character, string,
 * and sizing methods are built on them: the value's bytes are read into a temporary array, decoded,
 * and the array is then wiped. (The JVM has no stack or pinned arrays, so a compacting collector may
 * have left copies of the array elsewhere in the heap before it was wiped.)
 */
public abstract class ValueProviderBase implements ValueProvider {
    /** How many times a value is re-read when it grows between being sized and being read. */
    private static final int MAX_READ_ATTEMPTS = 3;

    /** For subclasses. */
    protected ValueProviderBase() {
    }

    @Override
    public abstract ValueStatus tryGetBytes(String key, ByteBuffer destination);

    /**
     * Gets the number of UTF-8 bytes needed to hold the value for the specified key.
     *
     * @param key the configuration key
     * @return the required room for {@link #tryGetBytes}, or empty if the key was not found
     */
    protected abstract OptionalInt findByteCount(String key);

    /**
     * {@inheritDoc}
     *
     * @throws ConfigurationKeyException the value kept changing size while it was read
     */
    @Override
    public ValueStatus tryGetChars(String key, CharBuffer destination) {
        return withBytes(key, value -> Text.tryDecode(value, destination) ? ValueStatus.FOUND : ValueStatus.DESTINATION_TOO_SMALL,
                ValueStatus.NOT_FOUND);
    }

    /**
     * {@inheritDoc}
     *
     * @throws ConfigurationKeyException the value kept changing size while it was read
     */
    @Override
    public Optional<String> findValue(String key) {
        return withBytes(key, value -> {
            var chars = Text.decode(value);
            try {
                return Optional.of(new String(chars));
            } finally {
                Text.zero(chars);
            }
        }, Optional.empty());
    }

    /**
     * Gets the number of characters needed to hold the value for the specified key.
     *
     * @param key the configuration key
     * @return the required room for {@link #tryGetChars}, or empty if the key was not found
     * @throws ConfigurationKeyException the value kept changing size while it was read
     */
    protected OptionalInt findCharCount(String key) {
        return withBytes(key, value -> {
            var chars = Text.decode(value);
            try {
                return OptionalInt.of(chars.length);
            } finally {
                Text.zero(chars);
            }
        }, OptionalInt.empty());
    }

    @FunctionalInterface
    private interface BytesUse<R> {
        R apply(ByteBuffer value);
    }

    /**
     * Reads the value's bytes into a new array, hands them to use, and wipes the array. Re-reads a
     * value that outgrew the room its size called for, a few times.
     */
    private <R> R withBytes(String key, BytesUse<R> use, R notFound) {
        for (var attempt = 0; attempt < MAX_READ_ATTEMPTS; attempt++) {
            var byteCount = findByteCount(key);
            if (byteCount.isEmpty())
                return notFound;

            var buffer = new byte[byteCount.getAsInt()];
            try {
                var value = ByteBuffer.wrap(buffer);
                var status = tryGetBytes(key, value);
                if (status == ValueStatus.FOUND)
                    return use.apply(ByteBuffer.wrap(buffer, 0, value.position()));
                if (status == ValueStatus.NOT_FOUND)
                    return notFound;
            } finally {
                Text.zero(buffer);
            }
        }

        throw new ConfigurationKeyException(key, ConfigurationKeyError.VALUE_UNSTABLE);
    }
}
