package io.github.runsecure.hkdfguard.cache;

import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.ToIntFunction;

/**
 * Aggregates several {@link ProtectedReadOnlyCache} sources into one read-only surface. add
 * registers a source and returns this same instance for fluent chaining ({@code new
 * ProtectedCacheCollectionImpl().add(a).add(b)}). decrypt/findMaxDecryptedLength check each source
 * in the order it was added, returning the first match. This never owns or writes encrypted values
 * of its own - add only registers a source - so storing values stays the concern of whichever
 * sources support it (e.g. a writable {@link ProtectedCacheImpl} among them). Safe to read while
 * sources are being added.
 * <p>
 * decryptAsync and findMaxDecryptedLengthAsync ask each source with its own asynchronous member,
 * one after another, so a source that fetches over the network (a {@link RemoteSecretCache})
 * doesn't block; cancelling the returned future cancels the source being asked.
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

    @Override
    public CompletableFuture<Integer> decryptAsync(String name, byte[] result) {
        return decryptTraced(name, source -> source.decryptAsync(name, result));
    }

    @Override
    public CompletableFuture<Integer> decryptAsync(String name, char[] result) {
        return decryptTraced(name, source -> source.decryptAsync(name, result));
    }

    @Override
    public CompletableFuture<OptionalInt> findMaxDecryptedLengthAsync(String name) {
        var found = new CompletableFuture<OptionalInt>();
        askNext(sources.iterator(), source -> source.findMaxDecryptedLengthAsync(name), OptionalInt::isPresent, OptionalInt.empty(), found);
        return found;
    }

    // firstMatch, asking each source asynchronously; the span isn't made current, since a source
    // may answer on another thread, and ends when the returned future completes.
    private CompletableFuture<Integer> decryptTraced(String name, Function<ProtectedReadOnlyCache, CompletableFuture<Integer>> decrypt) {
        var telemetry = HkdfGuardTelemetry.CACHE;
        var span = telemetry.getTracer().spanBuilder(SpanNames.Cache.DECRYPT).startSpan();
        if (telemetry.isSensitiveLoggingEnabled())
            telemetry.logSensitiveOperation(span, SpanNames.Cache.DECRYPT, Attributes.of(NAME, String.valueOf(name)));

        var decrypted = new CompletableFuture<Integer>();
        askNext(sources.iterator(), decrypt, written -> written > 0, 0, decrypted);
        decrypted.whenComplete((written, error) -> {
            if (error != null)
                ComponentTelemetry.recordException(span, KeyWrapperFutures.unwrap(error));
            span.end();
        });
        return decrypted;
    }

    // Asks the next source, completing result with its answer when it matches, or asking the one
    // after when it doesn't; completes it with missing once every source has been asked.
    private static <T> void askNext(Iterator<ProtectedReadOnlyCache> remaining, Function<ProtectedReadOnlyCache, CompletableFuture<T>> ask,
            Predicate<T> matches, T missing, CompletableFuture<T> result) {
        if (result.isDone())
            return;
        if (!remaining.hasNext()) {
            result.complete(missing);
            return;
        }

        CompletableFuture<T> answer;
        try {
            answer = Objects.requireNonNull(ask.apply(remaining.next()), "a source returned no future");
        } catch (RuntimeException e) {
            result.completeExceptionally(e);
            return;
        }

        KeyWrapperFutures.cancelling(result, answer);
        answer.whenComplete((value, error) -> {
            if (error != null)
                result.completeExceptionally(KeyWrapperFutures.unwrap(error));
            else if (matches.test(value))
                result.complete(value);
            else
                askNext(remaining, ask, matches, missing, result);
        });
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
