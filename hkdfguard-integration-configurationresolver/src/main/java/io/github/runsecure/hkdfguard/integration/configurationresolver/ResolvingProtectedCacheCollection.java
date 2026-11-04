package io.github.runsecure.hkdfguard.integration.configurationresolver;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.abstractions.ProtectedCacheBase;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * {@code ProtectedCacheCollectionImpl} with templates: aggregates {@link ProtectedReadOnlyCache}
 * sources, checked in the order they were added, and resolves a value holding ConfigurationResolver
 * items - {@code "Host=db;Password=${db-password}"} - on its first lookup, from those same sources
 * (then any value providers added with {@link #addValueProvider}). The resolved value is encrypted
 * under the ring's current key, bound to its name as every {@link ProtectedCacheBase} entry is, and
 * cached, so later lookups only decrypt it. A value without items is answered by its source,
 * unchanged. The counterpart of .NET's {@code ResolvingProtectedCacheCollection}.
 * <p>
 * <b>Templates are trusted.</b> A template's items may name any value in any source, so every source
 * must be as trusted as the secrets it can reach: a template comes from whichever source holds its
 * name, and nothing marks one source as templates only. Items are resolved one level deep: an item
 * whose value is itself a template inserts that template's text unresolved. A value that is a
 * template but names a value no source or provider has throws {@code ConfigurationKeyException} on
 * lookup, rather than reporting the name missing. One that resolves to nothing is reported missing,
 * as an empty value can't be cached.
 * <p>
 * <b>Nothing becomes a String.</b> The template, each value it names and the result are held only in
 * arrays that are zeroed once used, and the result is cached encrypted.
 * <p>
 * <b>Resolved values are kept until invalidated.</b> When a value a template uses changes - a
 * {@code ProtectedCacheImpl.addOrUpdate}, a refreshed property source, a rotated remote secret - call
 * {@link #invalidate} for the template's name, or {@link #clear}; the next lookup resolves it again.
 * A resolution already under way when either is called doesn't cache its result. Which source holds
 * a value without items is remembered too, and forgotten the same way. Add every source and provider
 * before the first lookup.
 * <p>
 * A source that throws fails the lookup, as in {@code ProtectedCacheCollectionImpl}, and the same
 * advice holds: add local sources before remote ones. {@code decryptAsync} and
 * {@code findMaxDecryptedLengthAsync} find the value and every value its template names with each
 * source's asynchronous members, so a remote source doesn't block; the synchronous members block on
 * a remote fetch. Cancelling a returned future stops waiting for it, not a fetch already under way.
 */
public final class ResolvingProtectedCacheCollection implements ProtectedReadOnlyCache {
    /** The default {@link #maxResolvedLength()}: 1 MiB. */
    public static final int DEFAULT_MAX_RESOLVED_LENGTH = 1 << 20;

    private static final AttributeKey<String> NAME = AttributeKey.stringKey(AttributeNames.NAME);

    private final KeyRing keyRing;
    private final ConfigurationItemTokenBase token;
    private final int maxResolvedLength;
    private final List<ProtectedReadOnlyCache> sources = new CopyOnWriteArrayList<>();
    private final List<ValueProvider> valueProviders = new CopyOnWriteArrayList<>();
    private final ConcurrentHashMap<String, ProtectedReadOnlyCache> plain = new ConcurrentHashMap<>();
    private final Object gate = new Object();
    // Replaced, not emptied, by clear(); both written under gate.
    private volatile ResolvedStore resolved;
    private volatile long generation;

    /**
     * An empty collection, with the default token (<code>$&#123;</code>, <code>&#125;</code>, escape {@code $})
     * and a 1 MiB limit on resolved values.
     *
     * @param keyRing encrypts each resolved value under its current key, and decrypts it under the
     *                version it recorded. Owned by the caller
     */
    public ResolvingProtectedCacheCollection(KeyRing keyRing) {
        this(keyRing, new DefaultToken(), DEFAULT_MAX_RESOLVED_LENGTH);
    }

    /**
     * An empty collection.
     *
     * @param keyRing           encrypts each resolved value under its current key, and decrypts it
     *                          under the version it recorded. Owned by the caller
     * @param token             the token that marks an item
     * @param maxResolvedLength the most UTF-8 bytes a resolved value may hold; a template that
     *                          resolves to more throws {@link IllegalStateException} on lookup
     * @throws IllegalArgumentException maxResolvedLength is less than 1
     */
    public ResolvingProtectedCacheCollection(KeyRing keyRing, ConfigurationItemTokenBase token, int maxResolvedLength) {
        this.keyRing = Objects.requireNonNull(keyRing, "keyRing");
        this.token = Objects.requireNonNull(token, "token");
        if (maxResolvedLength < 1)
            throw new IllegalArgumentException("maxResolvedLength must be at least 1.");
        this.maxResolvedLength = maxResolvedLength;
        this.resolved = new ResolvedStore(keyRing);
    }

    /**
     * The token that marks an item.
     *
     * @return the token
     */
    public ConfigurationItemTokenBase token() {
        return token;
    }

    /**
     * The most UTF-8 bytes a resolved value may hold.
     *
     * @return the limit
     */
    public int maxResolvedLength() {
        return maxResolvedLength;
    }

    /**
     * Registers {@code source}, checked after every source already added - for names and for the
     * items in templates alike.
     *
     * @param source the source
     * @return this same collection, for fluent chaining
     */
    public ResolvingProtectedCacheCollection add(ProtectedReadOnlyCache source) {
        sources.add(Objects.requireNonNull(source, "source"));
        return this;
    }

    /**
     * Registers a value provider - any {@link ValueProvider}, such as one over plain settings - for
     * the items in templates only, asked after every source and every provider already added. Its
     * values are never answered by name on their own. A provider that holds its values as strings is
     * no place for secrets.
     *
     * @param valueProvider the provider
     * @return this same collection, for fluent chaining
     */
    public ResolvingProtectedCacheCollection addValueProvider(ValueProvider valueProvider) {
        valueProviders.add(Objects.requireNonNull(valueProvider, "valueProvider"));
        return this;
    }

    /**
     * Forgets name's resolved value, or which source holds it, so the next lookup reads it again.
     *
     * @param name the name, exactly as it is looked up
     * @return true if anything was remembered for name
     */
    public boolean invalidate(String name) {
        var key = storeKey(name);
        synchronized (gate) {
            generation++;
            var removed = resolved.remove(key);
            return plain.remove(name) != null | removed;
        }
    }

    /** Forgets every resolved value, and every source a value was found in. */
    public void clear() {
        synchronized (gate) {
            generation++;
            resolved = new ResolvedStore(keyRing);
            plain.clear();
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws io.github.runsecure.hkdfguard.integration.configurationresolver.ConfigurationKeyException name's
     *         value is a template naming a value nothing has
     * @throws IllegalStateException name's value resolves to more than {@link #maxResolvedLength()}
     *                               bytes
     */
    @Override
    public int decrypt(String name, byte[] result) {
        Objects.requireNonNull(result, "result");
        return decryptTraced(name, (cache, n) -> cache.decrypt(n, result));
    }

    /**
     * {@inheritDoc}
     *
     * @throws io.github.runsecure.hkdfguard.integration.configurationresolver.ConfigurationKeyException name's
     *         value is a template naming a value nothing has
     * @throws IllegalStateException name's value resolves to more than {@link #maxResolvedLength()}
     *                               bytes
     */
    @Override
    public int decrypt(String name, char[] result) {
        Objects.requireNonNull(result, "result");
        return decryptTraced(name, (cache, n) -> cache.decrypt(n, result));
    }

    /**
     * {@inheritDoc}
     *
     * @throws io.github.runsecure.hkdfguard.integration.configurationresolver.ConfigurationKeyException name's
     *         value is a template naming a value nothing has
     * @throws IllegalStateException name's value resolves to more than {@link #maxResolvedLength()}
     *                               bytes
     */
    @Override
    public OptionalInt findMaxDecryptedLength(String name) {
        return lookup(name, ProtectedReadOnlyCache::findMaxDecryptedLength, OptionalInt::isPresent, OptionalInt.empty());
    }

    /**
     * {@inheritDoc}
     * <p>
     * Fails with {@code ConfigurationKeyException} or {@link IllegalStateException} as
     * {@link #decrypt(String, byte[])} throws them.
     */
    @Override
    public CompletableFuture<Integer> decryptAsync(String name, byte[] result) {
        return decryptTracedAsync(name, result, (cache, n) -> cache.decrypt(n, result), (cache, n) -> cache.decryptAsync(n, result));
    }

    /**
     * {@inheritDoc}
     * <p>
     * Fails with {@code ConfigurationKeyException} or {@link IllegalStateException} as
     * {@link #decrypt(String, char[])} throws them.
     */
    @Override
    public CompletableFuture<Integer> decryptAsync(String name, char[] result) {
        return decryptTracedAsync(name, result, (cache, n) -> cache.decrypt(n, result), (cache, n) -> cache.decryptAsync(n, result));
    }

    /**
     * {@inheritDoc}
     * <p>
     * Fails with {@code ConfigurationKeyException} or {@link IllegalStateException} as
     * {@link #findMaxDecryptedLength} throws them.
     */
    @Override
    public CompletableFuture<OptionalInt> findMaxDecryptedLengthAsync(String name) {
        return start(() -> lookupAsync(name, storeKey(name), ProtectedReadOnlyCache::findMaxDecryptedLength,
                ProtectedReadOnlyCache::findMaxDecryptedLengthAsync, OptionalInt::isPresent, OptionalInt.empty()));
    }

    private enum Location {
        /** No source holds the name, or its template resolved to nothing. */
        MISSING,
        /** A source holds the name, and its value has no items: that source answers. */
        SOURCE,
        /**
         * The name's template was resolved: look in the resolved store again. If an invalidate or
         * clear kept the result out of it, the lookup resolves it again.
         */
        RESOLVED,
    }

    private record Found(Location location, ProtectedReadOnlyCache source) {
        static final Found MISSING = new Found(Location.MISSING, null);
        static final Found RESOLVED = new Found(Location.RESOLVED, null);
    }

    /** The first source holding a name, and its bound on the name's value. */
    private record Match(ProtectedReadOnlyCache source, int maxLength) {
    }

    /** A value holding items, in an array zeroed once it is resolved, and the reader that read them. */
    private record Template(byte[] value, int length, ConfigurationItemReaderImpl reader) {
    }

    private int decryptTraced(String name, BiFunction<ProtectedReadOnlyCache, String, Integer> read) {
        var telemetry = HkdfGuardTelemetry.CACHE;
        try (var op = telemetry.startSpan(SpanNames.Cache.DECRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.Cache.DECRYPT, Attributes.of(NAME, String.valueOf(name)));

            try {
                return lookup(name, read, written -> written > 0, 0);
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    // decryptTraced through each source's asynchronous members; the span isn't made current, since
    // a source may answer on another thread, and ends when the returned future completes.
    private CompletableFuture<Integer> decryptTracedAsync(String name, Object result, BiFunction<ProtectedReadOnlyCache, String, Integer> read,
                                                          BiFunction<ProtectedReadOnlyCache, String, CompletableFuture<Integer>> readAsync) {
        var telemetry = HkdfGuardTelemetry.CACHE;
        var span = telemetry.getTracer().spanBuilder(SpanNames.Cache.DECRYPT).startSpan();
        if (telemetry.isSensitiveLoggingEnabled())
            telemetry.logSensitiveOperation(span, SpanNames.Cache.DECRYPT, Attributes.of(NAME, String.valueOf(name)));

        var decrypted = start(() -> {
            Objects.requireNonNull(result, "result");
            return lookupAsync(name, storeKey(name), read, readAsync, written -> written > 0, 0);
        });
        decrypted.whenComplete((written, error) -> {
            if (error != null)
                ComponentTelemetry.recordException(span, KeyWrapperFutures.unwrap(error));
            span.end();
        });
        return decrypted;
    }

    private <T> T lookup(String name, BiFunction<ProtectedReadOnlyCache, String, T> read, Predicate<T> hit, T missing) {
        var key = storeKey(name);
        while (true) {
            var cached = read.apply(resolved, key);
            if (hit.test(cached))
                return cached;

            var found = join(locate(name, false));
            if (found.location() != Location.RESOLVED)
                return found.source() == null ? missing : read.apply(found.source(), name);
        }
    }

    private <T> CompletableFuture<T> lookupAsync(String name, String key, BiFunction<ProtectedReadOnlyCache, String, T> read,
                                                 BiFunction<ProtectedReadOnlyCache, String, CompletableFuture<T>> readAsync,
                                                 Predicate<T> hit, T missing) {
        // The resolved store is in memory: reading it never blocks.
        var cached = read.apply(resolved, key);
        if (hit.test(cached))
            return CompletableFuture.completedFuture(cached);

        return locate(name, true).thenCompose(found -> {
            if (found.location() == Location.RESOLVED)
                return lookupAsync(name, key, read, readAsync, hit, missing);
            return found.source() == null ? CompletableFuture.completedFuture(missing) : readAsync.apply(found.source(), name);
        });
    }

    /**
     * Finds name's value outside the resolved store, resolving and caching it on the way when it is a
     * template. When async, the value and every value its template names are found through each
     * source's asynchronous members, so resolving then reads only from memory; otherwise every future
     * here is complete when returned.
     */
    private CompletableFuture<Found> locate(String name, boolean async) {
        var known = plain.get(name);
        if (known != null)
            return CompletableFuture.completedFuture(new Found(Location.SOURCE, known));

        var startGeneration = generation;
        return findSource(sources.iterator(), name, async).thenCompose(match -> {
            if (match == null)
                return CompletableFuture.completedFuture(Found.MISSING);

            // The source has the value in hand now, so reading it doesn't fetch.
            var template = readTemplate(match.source(), name, match.maxLength());
            if (template == null)
                return CompletableFuture.completedFuture(remember(name, match.source(), startGeneration));

            return sumBounds(template.reader().keys().iterator(), async, template.length())
                    .thenApply(bound -> resolve(name, template, bound, startGeneration))
                    .whenComplete((found, error) -> ArrayUtility.zeroMemory(template.value()));
        });
    }

    // The first source holding name, as ProtectedCacheCollectionImpl finds it; null if none does.
    private static CompletableFuture<Match> findSource(Iterator<ProtectedReadOnlyCache> remaining, String name, boolean async) {
        if (!remaining.hasNext())
            return CompletableFuture.completedFuture(null);

        var source = remaining.next();
        var maxLength = async
                ? Objects.requireNonNull(source.findMaxDecryptedLengthAsync(name), "a source returned no future")
                : CompletableFuture.completedFuture(source.findMaxDecryptedLength(name));
        return maxLength.thenCompose(length -> length.isPresent()
                ? CompletableFuture.completedFuture(new Match(source, length.getAsInt()))
                : findSource(remaining, name, async));
    }

    // The sources' bounds on every value the template names, added to its own length; a key no
    // source has adds nothing, and is left to a value provider or reported by the resolver.
    private CompletableFuture<Long> sumBounds(Iterator<String> keys, boolean async, long bound) {
        if (!keys.hasNext())
            return CompletableFuture.completedFuture(bound);
        return findSource(sources.iterator(), keys.next(), async)
                .thenCompose(match -> sumBounds(keys, async, bound + (match == null ? 0 : match.maxLength())));
    }

    /**
     * Name's value from source, with a reader that has read its items - or null, the array already
     * zeroed, when it holds none.
     */
    private Template readTemplate(ProtectedReadOnlyCache source, String name, int maxLength) {
        var value = new byte[maxLength];
        try {
            var length = source.decrypt(name, value);
            var reader = new ConfigurationItemReaderImpl(token);
            if (!reader.readKeys(ByteBuffer.wrap(value, 0, length)).isEmpty())
                return new Template(value, length, reader);
        } catch (RuntimeException | Error e) {
            ArrayUtility.zeroMemory(value);
            throw e;
        }
        ArrayUtility.zeroMemory(value);
        return null;
    }

    private Found remember(String name, ProtectedReadOnlyCache source, long startGeneration) {
        synchronized (gate) {
            if (startGeneration == generation)
                plain.put(name, source);
        }
        return new Found(Location.SOURCE, source);
    }

    /**
     * Resolves template and caches the result under name - unless invalidate or clear was called since
     * startGeneration was read, when the result is dropped for the lookup to resolve again.
     */
    private Found resolve(String name, Template template, long bound, long startGeneration) {
        var providers = new ArrayList<ValueProvider>();
        for (var source : sources)
            providers.add(new ProtectedCacheValueProvider(source));
        providers.addAll(valueProviders);
        var resolver = new ConfigurationItemResolver(token, template.reader(), providers);

        // The sources' bounds cover their values; a value provider's can't be known up front, so a
        // value from one may need a larger buffer.
        var capacity = (int) Math.max(1, Math.min(bound, maxResolvedLength));
        while (true) {
            var value = new byte[capacity];
            try {
                int written;
                try {
                    written = resolver.resolve(ByteBuffer.wrap(template.value(), 0, template.length()), ByteBuffer.wrap(value));
                } catch (DestinationTooSmallException e) {
                    if (capacity >= maxResolvedLength)
                        throw new IllegalStateException("The value resolves to more than maxResolvedLength (" + maxResolvedLength + ") bytes.", e);
                    capacity = (int) Math.min(2L * capacity, maxResolvedLength);
                    continue;
                }

                if (written == 0)
                    return Found.MISSING;

                synchronized (gate) {
                    // encrypt zeroes the copy it is given.
                    if (startGeneration == generation)
                        resolved.set(storeKey(name), Arrays.copyOf(value, written));
                }
                return Found.RESOLVED;
            } finally {
                ArrayUtility.zeroMemory(value);
            }
        }
    }

    // The resolved store matches names ignoring ASCII case, as every ProtectedCacheBase does; this
    // collection matches them exactly, as its sources may. So each name is stored under a spelling
    // with no lower-case ASCII: '!' becomes "!!", and a lower-case letter '!' and its upper-case form.
    static String storeKey(String name) {
        Objects.requireNonNull(name, "name");
        var plainSpelling = true;
        for (var i = 0; i < name.length() && plainSpelling; i++) {
            var c = name.charAt(i);
            plainSpelling = c != '!' && (c < 'a' || c > 'z');
        }
        if (plainSpelling)
            return name;

        var key = new StringBuilder(name.length() + 8);
        for (var i = 0; i < name.length(); i++) {
            var c = name.charAt(i);
            if (c == '!')
                key.append("!!");
            else if (c >= 'a' && c <= 'z')
                key.append('!').append((char) (c - ('a' - 'A')));
            else
                key.append(c);
        }
        return key.toString();
    }

    // Runs a lookup that may throw before it has a future, reporting that through one.
    private static <T> CompletableFuture<T> start(Supplier<CompletableFuture<T>> lookup) {
        try {
            return lookup.get();
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    // A synchronous lookup's futures are already complete; report a failure as it was thrown.
    private static <T> T join(CompletableFuture<T> future) {
        try {
            return future.join();
        } catch (CompletionException e) {
            if (e.getCause() instanceof RuntimeException cause)
                throw cause;
            if (e.getCause() instanceof Error cause)
                throw cause;
            throw e;
        }
    }

    /** The resolved values, encrypted and bound to their (store-key) names. */
    private static final class ResolvedStore extends ProtectedCacheBase {
        ResolvedStore(KeyRing keyRing) {
            super(keyRing);
        }

        // encrypt zeroes plaintext.
        void set(String key, byte[] plaintext) {
            putEntry(key, encrypt(key, plaintext));
        }

        boolean remove(String key) {
            return removeEntry(key);
        }
    }
}
