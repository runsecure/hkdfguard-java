package io.github.runsecure.hkdfguard.cache;

import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.ToIntFunction;

/**
 * Aggregates several {@link ProtectedReadOnlyCache} sources into one read-only surface. add
 * registers a source and returns this same instance for fluent chaining ({@code new
 * ProtectedCacheCollectionImpl().add(a).add(b)}). decrypt/findMaxDecryptedLength check each source
 * in the order it was added, returning the first match. This never owns or writes encrypted values
 * of its own - add only registers a source - so storing values stays the concern of whichever
 * sources support it (e.g. a writable {@link ProtectedCacheImpl} among them). Safe to read while
 * sources are being added.
 */
public final class ProtectedCacheCollectionImpl implements ProtectedReadOnlyCache {
    private static final AttributeKey<String> NAME = AttributeKey.stringKey(AttributeNames.NAME);

    private final List<ProtectedReadOnlyCache> sources = new CopyOnWriteArrayList<>();

    /** An empty collection: every lookup misses until a source is added. */
    public ProtectedCacheCollectionImpl() {
    }

    /**
     * Registers {@code source}, checked after every source already added.
     *
     * @return this same collection, for fluent chaining
     */
    public ProtectedCacheCollectionImpl add(ProtectedReadOnlyCache source) {
        sources.add(Objects.requireNonNull(source, "source"));
        return this;
    }

    @Override
    public int decrypt(String name, byte[] result) {
        return firstMatch(name, source -> source.decrypt(name, result));
    }

    @Override
    public int decrypt(String name, char[] result) {
        return firstMatch(name, source -> source.decrypt(name, result));
    }

    @Override
    public OptionalInt findMaxDecryptedLength(String name) {
        for (var source : sources) {
            var maxLength = source.findMaxDecryptedLength(name);
            if (maxLength.isPresent())
                return maxLength;
        }
        return OptionalInt.empty();
    }

    private int firstMatch(String name, ToIntFunction<ProtectedReadOnlyCache> decrypt) {
        var telemetry = HkdfGuardTelemetry.CACHE;
        try (var op = telemetry.startSpan(SpanNames.Cache.DECRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.Cache.DECRYPT, Attributes.of(NAME, String.valueOf(name)));

            try {
                for (var source : sources) {
                    var written = decrypt.applyAsInt(source);
                    if (written > 0)
                        return written;
                }
                return 0;
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }
}
