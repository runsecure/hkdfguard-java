package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Resolves text by replacing the configuration items delimited by a
 * {@link ConfigurationItemTokenBase} with values from one or more {@link ValueProvider}s, for only the
 * keys read by a {@link ConfigurationItemReader}.
 * <p>
 * Keys are trimmed of surrounding whitespace, the same as
 * {@link io.github.runsecure.hkdfguard.integration.configurationresolver.ConfigurationItemReaderImpl}. Only keys
 * returned by the reader's {@link ConfigurationItemReader#keys() keys} are looked up, so read the
 * keys from a trusted template first; any other key throws without the provider being asked for it.
 * With several value providers, each key is looked up in the order the providers were given, and the
 * first provider that has the key supplies the value, as with {@link CompositeValueProvider}. A key
 * that is not allowed throws a {@link ConfigurationKeyException}, whose message does not contain the
 * key. A key that no provider has throws the same way, unless
 * {@link #ignoreUnresolvablePlaceholders()} is set. The reader's keys are checked each time
 * {@code resolve} is called, so the most recent read applies. Empty items such as {@code ${}} and a
 * start sequence with no matching end sequence are copied unchanged, and a start sequence preceded by
 * the token's escape sequence is copied without the escape sequence. By default values are inserted
 * as they are; use {@link #withMaxResolutionDepth} to also resolve the items inside values.
 * <p>
 * Values are written by the provider directly into the destination and are never read as strings.
 * If resolving fails, the destination is wiped from its position to its limit, so no partially
 * resolved values are left behind.
 */
public class ConfigurationItemResolver implements ConfigurationResolver {
    private final ConfigurationItemReader reader;
    private final ValueProvider valueProvider;
    private final Units<CharBuffer> charUnits;
    private final Units<ByteBuffer> utf8Units;
    private final boolean ignoreUnresolvablePlaceholders;
    private final int maxResolutionDepth;

    /**
     * @param token          the token that defines the start, end, and escape sequences of a
     *                       configuration item
     * @param reader         the reader whose keys are the only keys that may be resolved
     * @param valueProviders the providers used to resolve the value of each key, highest priority first
     * @throws NullPointerException     token, reader, or valueProviders is null
     * @throws IllegalArgumentException valueProviders is empty or contains null
     */
    public ConfigurationItemResolver(ConfigurationItemTokenBase token, ConfigurationItemReader reader, ValueProvider... valueProviders) {
        this(token, reader, Arrays.asList(Objects.requireNonNull(valueProviders, "valueProviders")));
    }

    /**
     * @param token          the token that defines the start, end, and escape sequences of a
     *                       configuration item
     * @param reader         the reader whose keys are the only keys that may be resolved
     * @param valueProviders the providers used to resolve the value of each key, highest priority first
     * @throws NullPointerException     token, reader, or valueProviders is null
     * @throws IllegalArgumentException valueProviders is empty or contains null
     */
    public ConfigurationItemResolver(ConfigurationItemTokenBase token, ConfigurationItemReader reader, Iterable<? extends ValueProvider> valueProviders) {
        Objects.requireNonNull(token, "token");
        this.reader = Objects.requireNonNull(reader, "reader");
        var composite = new CompositeValueProvider(Objects.requireNonNull(valueProviders, "valueProviders"));
        this.valueProvider = composite.getProviders().size() == 1 ? composite.getProviders().get(0) : composite;
        var escape = token.getEscapeSequence();
        this.charUnits = new CharUnits(token.getStartSequence().toCharArray(), token.getEndSequence().toCharArray(),
                escape == null ? new char[0] : escape.toCharArray());
        this.utf8Units = new Utf8Units(token.getStartSequence().getBytes(StandardCharsets.UTF_8), token.getEndSequence().getBytes(StandardCharsets.UTF_8),
                escape == null ? new byte[0] : escape.getBytes(StandardCharsets.UTF_8));
        this.ignoreUnresolvablePlaceholders = false;
        this.maxResolutionDepth = 1;
    }

    private ConfigurationItemResolver(ConfigurationItemResolver other, boolean ignoreUnresolvablePlaceholders, int maxResolutionDepth) {
        this.reader = other.reader;
        this.valueProvider = other.valueProvider;
        this.charUnits = other.charUnits;
        this.utf8Units = other.utf8Units;
        this.ignoreUnresolvablePlaceholders = ignoreUnresolvablePlaceholders;
        this.maxResolutionDepth = maxResolutionDepth;
    }

    /**
     * Whether an allowed key that no value provider has is copied to the destination unchanged, start
     * and end sequences included, instead of throwing a {@link ConfigurationKeyException} with
     * {@link ConfigurationKeyError#NOT_FOUND}. False by default.
     * <p>
     * A key that is not allowed still throws with {@link ConfigurationKeyError#NOT_ALLOWED}, and an
     * error reported by a value provider, such as {@link ConfigurationKeyError#VALUE_UNSTABLE}, still
     * propagates.
     *
     * @return whether unresolvable items are copied unchanged
     */
    public boolean ignoreUnresolvablePlaceholders() {
        return ignoreUnresolvablePlaceholders;
    }

    /**
     * This resolver, with {@link #ignoreUnresolvablePlaceholders()} as given.
     *
     * @param ignore whether to copy unresolvable items unchanged
     * @return a new resolver sharing this one's token, reader and providers
     */
    public ConfigurationItemResolver withIgnoreUnresolvablePlaceholders(boolean ignore) {
        return new ConfigurationItemResolver(this, ignore, maxResolutionDepth);
    }

    /**
     * The number of levels of configuration items that are resolved. 1 by default.
     * <p>
     * At 1, values are inserted exactly as they are, even if they contain items. At 2, the items in
     * each value are resolved too, and their values are inserted as they are; each further level
     * resolves one more level of values. Items in values follow the same rules as items in the source:
     * their keys must be allowed by the reader, and escape sequences in values are applied. Values at
     * the last level are inserted unchanged, escape sequences included. A key whose value leads back
     * to itself throws a {@link ConfigurationKeyException} with {@link ConfigurationKeyError#CYCLE}. An
     * error in a value reports the position of the item in the source that led to it. A value that is
     * resolved is held in a buffer that is wiped afterwards, and is never read as a string.
     *
     * @return the number of levels
     */
    public int maxResolutionDepth() {
        return maxResolutionDepth;
    }

    /**
     * This resolver, with {@link #maxResolutionDepth()} as given.
     *
     * @param maxResolutionDepth the number of levels; 1 inserts values as they are
     * @return a new resolver sharing this one's token, reader and providers
     * @throws IllegalArgumentException maxResolutionDepth is less than 1
     */
    public ConfigurationItemResolver withMaxResolutionDepth(int maxResolutionDepth) {
        if (maxResolutionDepth < 1)
            throw new IllegalArgumentException("maxResolutionDepth must be at least 1.");
        return new ConfigurationItemResolver(this, ignoreUnresolvablePlaceholders, maxResolutionDepth);
    }

    @Override
    public int resolve(CharSequence source, CharBuffer destination) {
        Objects.requireNonNull(source, "source");
        var text = source instanceof CharBuffer buffer ? buffer.slice() : CharBuffer.wrap(source);
        return resolve(text, Objects.requireNonNull(destination, "destination"), charUnits);
    }

    @Override
    public int resolve(ByteBuffer source, ByteBuffer destination) {
        Objects.requireNonNull(source, "source");
        return resolve(source.slice(), Objects.requireNonNull(destination, "destination"), utf8Units);
    }

    private <B extends Buffer> int resolve(B source, B destination, Units<B> units) {
        var allowedKeys = new HashSet<>(reader.keys());
        var start = destination.position();
        var target = units.slice(destination, start, destination.limit());
        var output = new Output<B>(target);

        try {
            write(source, output, units, allowedKeys, new ArrayList<>(), 1, -1);
            destination.position(start + output.written);
            return output.written;
        } catch (RuntimeException | Error e) {
            units.zero(target, 0, target.limit());
            throw e;
        }
    }

    /** The destination, a slice indexed from 0, and how much of it is written. */
    private static final class Output<B extends Buffer> {
        final B buffer;
        int written;

        Output(B buffer) {
            this.buffer = buffer;
        }
    }

    /**
     * Copies text, a buffer indexed from 0 to its limit, to the destination, replacing each
     * configuration item with its value. {@code resolving} holds the keys whose values are being
     * resolved, outermost first. {@code depth} is 1 for the source, 2 for a value in it, and so on.
     * {@code itemIndex} is the index of the item in the source that led to this text, or -1 for the
     * source itself.
     */
    private <B extends Buffer> void write(B text, Output<B> output, Units<B> units, Set<String> allowedKeys, List<String> resolving,
                                          int depth, int itemIndex) {
        var length = text.limit();
        var from = 0;

        while (true) {
            var startIndex = units.indexOf(text, units.start, from, length);
            if (startIndex < 0) {
                copy(units, text, from, length, output);
                return;
            }

            var keyStart = startIndex + units.start.length;
            int consumed;
            if (units.escapeLength() > 0 && units.endsWithEscape(text, from, startIndex)) {
                copy(units, text, from, startIndex - units.escapeLength(), output);
                copy(units, text, startIndex, keyStart, output);
                consumed = keyStart;
            } else {
                var endIndex = units.indexOf(text, units.end, keyStart, length);
                if (endIndex < 0) {
                    copy(units, text, from, length, output);
                    return;
                }

                consumed = endIndex + units.end.length;
                var key = units.key(text, keyStart, endIndex);
                if (key.isEmpty()) {
                    copy(units, text, from, consumed, output);
                } else {
                    copy(units, text, from, startIndex, output);
                    var sourceIndex = itemIndex >= 0 ? itemIndex : startIndex;
                    if (!tryWriteValue(key, sourceIndex, output, units, allowedKeys, resolving, depth))
                        copy(units, text, startIndex, consumed, output);
                }
            }

            from = consumed;
        }
    }

    /**
     * Writes the value of a key to the destination, resolving the items in it if the depth allows.
     *
     * @return true if the value was written; false if no provider has the key and
     *         ignoreUnresolvablePlaceholders is set, so the item is to be copied unchanged
     */
    private <B extends Buffer> boolean tryWriteValue(String key, int sourceIndex, Output<B> output, Units<B> units, Set<String> allowedKeys,
                                                     List<String> resolving, int depth) {
        if (!allowedKeys.contains(key))
            throw new ConfigurationKeyException(key, ConfigurationKeyError.NOT_ALLOWED, sourceIndex);
        if (resolving.contains(key))
            throw new ConfigurationKeyException(key, ConfigurationKeyError.CYCLE, sourceIndex);

        var view = units.slice(output.buffer, output.written, output.buffer.limit());
        ValueStatus status;
        try {
            status = Objects.requireNonNull(units.tryGetValue(valueProvider, key, view), "a value provider returned no status");
        } catch (ConfigurationKeyException e) {
            if (e.getSourceIndex().isPresent())
                throw e;
            throw new ConfigurationKeyException(e.getKey(), e.getError(), sourceIndex, e);
        }

        if (status == ValueStatus.NOT_FOUND && ignoreUnresolvablePlaceholders)
            return false;
        if (status == ValueStatus.DESTINATION_TOO_SMALL)
            throw new DestinationTooSmallException();
        if (status != ValueStatus.FOUND)
            throw new ConfigurationKeyException(key, ConfigurationKeyError.NOT_FOUND, sourceIndex);

        var valueStart = output.written;
        var valueLength = view.position();
        if (depth >= maxResolutionDepth || units.indexOf(output.buffer, units.start, valueStart, valueStart + valueLength) < 0) {
            output.written += valueLength;
            return true;
        }

        // Move the value to a copy, wipe it from the destination, and write it back resolved.
        var copy = units.allocate(valueLength);
        try {
            units.copy(output.buffer, valueStart, valueStart + valueLength, copy, 0);
            units.zero(output.buffer, valueStart, valueStart + valueLength);

            resolving.add(key);
            write(copy, output, units, allowedKeys, resolving, depth + 1, sourceIndex);
            resolving.remove(resolving.size() - 1);
        } finally {
            units.zero(copy, 0, valueLength);
        }
        return true;
    }

    private static <B extends Buffer> void copy(Units<B> units, B text, int from, int to, Output<B> output) {
        var length = to - from;
        if (length > output.buffer.limit() - output.written)
            throw new DestinationTooSmallException();
        units.copy(text, from, to, output.buffer, output.written);
        output.written += length;
    }

    /**
     * The operations that differ between resolving characters and resolving UTF-8 bytes. Every index
     * is absolute, in a buffer whose index 0 is its start.
     */
    private abstract static class Units<B extends Buffer> {
        final int[] start;
        final int[] end;
        final int[] escape;

        Units(int[] start, int[] end, int[] escape) {
            this.start = start;
            this.end = end;
            this.escape = escape;
        }

        abstract int at(B text, int index);

        abstract void copy(B source, int from, int to, B destination, int at);

        abstract String key(B text, int from, int to);

        abstract ValueStatus tryGetValue(ValueProvider provider, String key, B destination);

        abstract B slice(B buffer, int from, int to);

        abstract B allocate(int length);

        abstract void zero(B buffer, int from, int to);

        int escapeLength() {
            return escape.length;
        }

        /** The index of sequence in text[from, to), or -1. */
        int indexOf(B text, int[] sequence, int from, int to) {
            var last = to - sequence.length;
            for (var i = from; i <= last; i++) {
                var j = 0;
                while (j < sequence.length && at(text, i + j) == sequence[j])
                    j++;
                if (j == sequence.length)
                    return i;
            }
            return -1;
        }

        /** Whether text[from, to) ends with the escape sequence. */
        boolean endsWithEscape(B text, int from, int to) {
            if (to - from < escape.length)
                return false;
            for (var j = 0; j < escape.length; j++)
                if (at(text, to - escape.length + j) != escape[j])
                    return false;
            return true;
        }
    }

    private static final class CharUnits extends Units<CharBuffer> {
        CharUnits(char[] start, char[] end, char[] escape) {
            super(widen(start), widen(end), widen(escape));
        }

        private static int[] widen(char[] chars) {
            var units = new int[chars.length];
            for (var i = 0; i < chars.length; i++)
                units[i] = chars[i];
            return units;
        }

        @Override
        int at(CharBuffer text, int index) {
            return text.get(index);
        }

        @Override
        void copy(CharBuffer source, int from, int to, CharBuffer destination, int at) {
            destination.put(at, source, from, to - from);
        }

        @Override
        String key(CharBuffer text, int from, int to) {
            return Text.trim(text, from, to);
        }

        @Override
        ValueStatus tryGetValue(ValueProvider provider, String key, CharBuffer destination) {
            return provider.tryGetChars(key, destination);
        }

        @Override
        CharBuffer slice(CharBuffer buffer, int from, int to) {
            return buffer.slice(from, to - from);
        }

        @Override
        CharBuffer allocate(int length) {
            return CharBuffer.allocate(length);
        }

        @Override
        void zero(CharBuffer buffer, int from, int to) {
            Text.zero(buffer, from, to);
        }
    }

    private static final class Utf8Units extends Units<ByteBuffer> {
        Utf8Units(byte[] start, byte[] end, byte[] escape) {
            super(widen(start), widen(end), widen(escape));
        }

        private static int[] widen(byte[] bytes) {
            var units = new int[bytes.length];
            for (var i = 0; i < bytes.length; i++)
                units[i] = bytes[i];
            return units;
        }

        @Override
        int at(ByteBuffer text, int index) {
            return text.get(index);
        }

        @Override
        void copy(ByteBuffer source, int from, int to, ByteBuffer destination, int at) {
            destination.put(at, source, from, to - from);
        }

        @Override
        String key(ByteBuffer text, int from, int to) {
            var chars = Text.decode(text.slice(from, to - from));
            try {
                return Text.trim(CharBuffer.wrap(chars), 0, chars.length);
            } finally {
                Text.zero(chars);
            }
        }

        @Override
        ValueStatus tryGetValue(ValueProvider provider, String key, ByteBuffer destination) {
            return provider.tryGetBytes(key, destination);
        }

        @Override
        ByteBuffer slice(ByteBuffer buffer, int from, int to) {
            return buffer.slice(from, to - from);
        }

        @Override
        ByteBuffer allocate(int length) {
            return ByteBuffer.allocate(length);
        }

        @Override
        void zero(ByteBuffer buffer, int from, int to) {
            Text.zero(buffer, from, to);
        }
    }
}
