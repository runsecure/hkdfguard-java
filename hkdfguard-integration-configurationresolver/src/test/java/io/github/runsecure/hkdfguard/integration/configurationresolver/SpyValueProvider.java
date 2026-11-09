package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** A value provider that records how the resolver calls it. */
final class SpyValueProvider implements ValueProvider {
    private final Map<String, String> values;
    private final RuntimeException throwOnLookup;

    final List<String> findValueCalls = new ArrayList<>();
    final List<String> tryGetCharsCalls = new ArrayList<>();
    final List<String> tryGetBytesCalls = new ArrayList<>();
    /** The room each tryGetChars or tryGetBytes call was given: its destination's remaining. */
    final List<Integer> bufferLengths = new ArrayList<>();

    SpyValueProvider(Map<String, String> values) {
        this(values, null);
    }

    /** A provider whose tryGetChars and tryGetBytes throw throwOnLookup, if it is not null. */
    SpyValueProvider(Map<String, String> values, RuntimeException throwOnLookup) {
        this.values = values;
        this.throwOnLookup = throwOnLookup;
    }

    @Override
    public Optional<String> findValue(String key) {
        findValueCalls.add(key);
        return Optional.ofNullable(values.get(key));
    }

    @Override
    public ValueStatus tryGetChars(String key, CharBuffer destination) {
        tryGetCharsCalls.add(key);
        bufferLengths.add(destination.remaining());
        throwIfConfigured();

        var value = values.get(key);
        if (value == null)
            return ValueStatus.NOT_FOUND;
        if (value.length() > destination.remaining())
            return ValueStatus.DESTINATION_TOO_SMALL;
        destination.put(value);
        return ValueStatus.FOUND;
    }

    @Override
    public ValueStatus tryGetBytes(String key, ByteBuffer destination) {
        tryGetBytesCalls.add(key);
        bufferLengths.add(destination.remaining());
        throwIfConfigured();

        var value = values.get(key);
        if (value == null)
            return ValueStatus.NOT_FOUND;
        var bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > destination.remaining())
            return ValueStatus.DESTINATION_TOO_SMALL;
        destination.put(bytes);
        return ValueStatus.FOUND;
    }

    private void throwIfConfigured() {
        if (throwOnLookup != null)
            throw throwOnLookup;
    }
}
