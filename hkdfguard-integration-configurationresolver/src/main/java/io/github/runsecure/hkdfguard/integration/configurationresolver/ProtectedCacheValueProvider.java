package io.github.runsecure.hkdfguard.integration.configurationresolver;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;

/**
 * A ConfigurationResolver value provider over a {@link ProtectedReadOnlyCache}, so the items in a
 * template - {@code "Password=${db-password}"} - resolve from HkdfGuard's protected caches: a
 * {@code ProtectedCacheImpl}, a file-per-secret cache, a {@code ProtectedEnvironment}, or a remote
 * secret store's cache (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, Google Secret
 * Manager). A template's key is the cache's name as it is, so a remote cache's
 * {@code app-config#api-key} form works unchanged. The counterpart of .NET's
 * {@code ProtectedCacheValueProvider}.
 * <p>
 * Each value is decrypted into a scratch array sized by the cache's bound, copied into the
 * resolver's destination, and the scratch array zeroed. It is never a string: {@link #findValue},
 * the one {@code ValueProvider} member that returns one, throws unless string values were allowed.
 * The resolver itself never calls it.
 * <p>
 * {@code ValueProvider} is synchronous, so a remote cache fetches a value it hasn't cached yet by
 * blocking the resolving thread. Call {@link #prefetchAsync(ConfigurationItemReader)} with the
 * template's reader first: the cache keeps what it fetches, so resolving then reads only from memory.
 */
public final class ProtectedCacheValueProvider extends ValueProviderBase {
    private final ProtectedReadOnlyCache cache;
    private final boolean allowStringValues;

    /**
     * A provider whose {@link #findValue} throws.
     *
     * @param cache the cache values are read from
     * @throws NullPointerException cache is null
     */
    public ProtectedCacheValueProvider(ProtectedReadOnlyCache cache) {
        this(cache, false);
    }

    /**
     * @param cache             the cache values are read from
     * @param allowStringValues whether {@link #findValue} may return a value as a string, which can't
     *                          be zeroed; when false it throws {@link IllegalStateException} instead
     * @throws NullPointerException cache is null
     */
    public ProtectedCacheValueProvider(ProtectedReadOnlyCache cache, boolean allowStringValues) {
        this.cache = Objects.requireNonNull(cache, "cache");
        this.allowStringValues = allowStringValues;
    }

    /**
     * The cache values are read from.
     *
     * @return the cache
     */
    public ProtectedReadOnlyCache cache() {
        return cache;
    }

    /**
     * Whether {@link #findValue} may return a value as a string.
     *
     * @return whether string values are allowed
     */
    public boolean allowStringValues() {
        return allowStringValues;
    }

    /**
     * Fetches every key the reader has read, without blocking, so a later resolve doesn't fetch. A key
     * the cache doesn't have is skipped; resolving reports it.
     *
     * @param reader the reader the resolver was given, after it has read the template
     * @return completes once every key has been asked for; cancelling it stops waiting
     * @throws NullPointerException reader is null
     */
    public CompletableFuture<Void> prefetchAsync(ConfigurationItemReader reader) {
        Objects.requireNonNull(reader, "reader");
        return prefetchAsync(reader.keys());
    }

    /**
     * Fetches each of {@code keys}, one at a time and without blocking, so a later resolve doesn't
     * fetch. A key the cache doesn't have is skipped; resolving reports it.
     *
     * @param keys the keys to fetch; a key listed twice is fetched once
     * @return completes once every key has been asked for; cancelling it stops waiting
     * @throws NullPointerException keys is null
     */
    public CompletableFuture<Void> prefetchAsync(Iterable<String> keys) {
        Objects.requireNonNull(keys, "keys");
        var distinct = new LinkedHashSet<String>();
        keys.forEach(distinct::add);
        return prefetch(distinct.iterator());
    }

    private CompletableFuture<Void> prefetch(Iterator<String> remaining) {
        if (!remaining.hasNext())
            return CompletableFuture.completedFuture(null);
        return cache.findMaxDecryptedLengthAsync(remaining.next()).thenCompose(ignored -> prefetch(remaining));
    }

    @Override
    public ValueStatus tryGetBytes(String key, ByteBuffer destination) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(destination, "destination");
        var maxLength = cache.findMaxDecryptedLength(key);
        if (maxLength.isEmpty())
            return ValueStatus.NOT_FOUND;

        var plaintext = new byte[maxLength.getAsInt()];
        try {
            var length = cache.decrypt(key, plaintext);
            if (length == 0)
                return ValueStatus.NOT_FOUND;
            if (length > destination.remaining())
                return ValueStatus.DESTINATION_TOO_SMALL;

            destination.put(plaintext, 0, length);
            return ValueStatus.FOUND;
        } finally {
            ArrayUtility.zeroMemory(plaintext);
        }
    }

    @Override
    public ValueStatus tryGetChars(String key, CharBuffer destination) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(destination, "destination");
        // The bound counts UTF-8 bytes, and a value never has more chars than that.
        var maxLength = cache.findMaxDecryptedLength(key);
        if (maxLength.isEmpty())
            return ValueStatus.NOT_FOUND;

        var plaintext = new char[maxLength.getAsInt()];
        try {
            var length = cache.decrypt(key, plaintext);
            if (length == 0)
                return ValueStatus.NOT_FOUND;
            if (length > destination.remaining())
                return ValueStatus.DESTINATION_TOO_SMALL;

            destination.put(plaintext, 0, length);
            return ValueStatus.FOUND;
        } finally {
            ArrayUtility.zeroMemory(plaintext);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalStateException string values aren't allowed
     */
    @Override
    public Optional<String> findValue(String key) {
        if (!allowStringValues)
            throw new IllegalStateException("ProtectedCacheValueProvider doesn't return values as strings unless allowStringValues is set.");
        return super.findValue(key);
    }

    @Override
    protected OptionalInt findByteCount(String key) {
        return cache.findMaxDecryptedLength(Objects.requireNonNull(key, "key"));
    }
}
