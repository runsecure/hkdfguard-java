package io.github.runsecure.hkdfguard.cache;

import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import org.slf4j.Logger;

/**
 * A RemoteSecretCache over an in-memory map, matched as {@code matching} says. Names are valid
 * unless they are empty or hold a ':'. Every fetch is recorded, and {@link #onFetch} or
 * {@link #onFetchAsync} can replace one.
 */
final class FakeRemoteSecretCache extends RemoteSecretCache {
    private final SecretNameMatching matching;
    private final Map<String, String> secrets = new ConcurrentHashMap<>();

    /** Every name fetch was called with, in order. */
    final Queue<String> fetches = new ConcurrentLinkedQueue<>();

    /** Every name fetchAsync was called with, in order - whether or not it went on to fetch. */
    final Queue<String> asyncFetches = new ConcurrentLinkedQueue<>();

    /** When set, runs in place of the default fetch. */
    volatile BiConsumer<String, SecretValueSink> onFetch;

    /** When set, runs in place of fetchAsync's default, which calls fetch on a virtual thread. */
    volatile BiFunction<String, SecretValueSink, CompletableFuture<Void>> onFetchAsync;

    /** What a name without a key reads; null for the whole value. */
    volatile String defaultKeyToRead;

    FakeRemoteSecretCache(KeyRing keyRing, SecretNameMatching matching) {
        this(keyRing, matching, null);
    }

    FakeRemoteSecretCache(KeyRing keyRing, SecretNameMatching matching, Logger logger) {
        super(keyRing, matching, logger);
        this.matching = matching;
    }

    void set(String name, String value) {
        secrets.put(key(name), value);
    }

    private String key(String name) {
        return matching == SecretNameMatching.EXACT ? name : name.toLowerCase(java.util.Locale.ROOT);
    }

    @Override
    protected String defaultKey() {
        return defaultKeyToRead != null ? defaultKeyToRead : super.defaultKey();
    }

    @Override
    protected boolean isValidName(String name) {
        return !name.isEmpty() && name.indexOf(':') < 0;
    }

    @Override
    protected void fetch(String name, SecretValueSink value) {
        fetches.add(name);
        var handler = onFetch;
        if (handler != null) {
            handler.accept(name, value);
            return;
        }

        var secret = secrets.get(key(name));
        if (secret != null)
            value.setText(secret);
    }

    @Override
    protected CompletableFuture<Void> fetchAsync(String name, SecretValueSink value) {
        asyncFetches.add(name);
        var handler = onFetchAsync;
        return handler != null ? handler.apply(name, value) : super.fetchAsync(name, value);
    }
}
