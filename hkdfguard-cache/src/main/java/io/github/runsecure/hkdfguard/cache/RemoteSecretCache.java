package io.github.runsecure.hkdfguard.cache;

import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.abstractions.ProtectedCacheBase;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.CacheMetrics;
import io.github.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;

/**
 * The shared plumbing of a {@link ProtectedReadOnlyCache} over a remote secret store: nothing is
 * fetched up front; the first decrypt/findMaxDecryptedLength for a name that isn't cached yet calls
 * {@link #fetch} for that one secret, encrypts every value it hands over under the ring's current
 * key, and caches the ciphertext; every later lookup is served from the cache. A subclass supplies
 * only {@link #isValidName} and {@link #fetch} - one call that reads one secret by name, never a
 * listing.
 * <p>
 * A name is a secret's name, optionally followed by {@link #KEY_SEPARATOR} and a key:
 * "app-config#api-key" is the api-key key of the secret app-config, which {@link #fetch} hands over
 * with {@link SecretValueSink#setKeyBytes} (or, for a secret holding a JSON object,
 * {@link SecretValueSink#setBytesWithJsonKeys}), and "app-config" is the secret's whole value, or its
 * {@link #defaultKey} where the store has one. One fetch caches the whole value and every key it
 * hands over, so the first lookup of any of them fetches the secret once and the rest are already
 * cached. A key is 1-{@link #MAX_KEY_LENGTH} printable ASCII characters other than space, '!' and
 * '#' (see {@link #isValidKey}), and is matched exactly whatever the store's matching.
 * <p>
 * A name whose secret {@link #isValidName} rejects, or whose key isn't one, is reported missing
 * without a fetch, so a cache can sit in a {@link ProtectedCacheCollectionImpl} beside sources with
 * other naming rules. A name the fetch hands no value for, or an empty one, is reported missing -
 * decrypt returns 0 - and isn't remembered, so it is fetched again on the next request (a key a
 * cached secret doesn't hold costs a fetch every time). An exception from {@link #fetch} propagates
 * to the caller unchanged, and nothing that fetch handed over is cached. Concurrent lookups of the
 * same uncached secret - of any of its keys, synchronous or asynchronous - share one fetch. A
 * cached value is kept for the life of the instance: a later fetch of the same secret adds keys
 * that weren't cached yet, but never replaces one that was.
 * <p>
 * decryptAsync and findMaxDecryptedLengthAsync fetch through {@link #fetchAsync}, which a store
 * with an asynchronous client overrides, so a miss doesn't block the caller's thread; decrypt and
 * findMaxDecryptedLength fetch through {@link #fetch}, blocking until it returns. Cancelling a
 * lookup's future cancels the fetch only if that lookup started it; a lookup whose shared fetch was
 * cancelled by the lookup that started it starts a new one.
 * <p>
 * Encryption, name binding and key rotation are {@link ProtectedCacheBase}'s. It matches names
 * ignoring ASCII case, so keys - and, under {@link SecretNameMatching#EXACT}, secret names - are
 * stored there under a case-escaped spelling: every upper-case ASCII letter becomes '!' and its
 * lower-case form, so "prod/Db" and "prod/db" are different entries, each bound to its own
 * spelling.
 * <p>
 * Telemetry: each fetch is a {@link SpanNames.Cache#POPULATE} span on
 * {@link HkdfGuardTelemetry#CACHE}, counted in {@link CacheMetrics#operations()} as "success",
 * "not_found" or "error"; with sensitive logging on, the secret's name (never a value) is logged.
 */
public abstract class RemoteSecretCache implements ProtectedReadOnlyCache {
    /** Separates a secret's name from a key it holds: "app-config#api-key". */
    public static final char KEY_SEPARATOR = '#';

    /** The longest key a name can hold. */
    public static final int MAX_KEY_LENGTH = 256;

    private static final char UPPER_CASE_MARKER = '!';

    private static final AttributeKey<String> NAME = AttributeKey.stringKey(AttributeNames.NAME);
    private static final AttributeKey<String> OPERATION_NAME = AttributeKey.stringKey(AttributeNames.OPERATION_NAME);
    private static final AttributeKey<String> RESULT = AttributeKey.stringKey(AttributeNames.RESULT);

    private final Store store;
    private final SecretNameMatching matching;
    private final Logger logger;

    /**
     * @param keyRing  supplies the key every fetched secret is encrypted under. Owned by the
     *                 caller: the cache never closes keys.
     * @param matching how the secret store matches names
     * @param logger   optional; receives a debug log per fetched name when sensitive logging is
     *                 enabled, and an error log per failed fetch
     * @throws NullPointerException keyRing or matching is null
     */
    protected RemoteSecretCache(KeyRing keyRing, SecretNameMatching matching, Logger logger) {
        this.store = new Store(this, Objects.requireNonNull(keyRing, "keyRing"));
        this.matching = Objects.requireNonNull(matching, "matching");
        this.logger = logger;
    }

    /**
     * The key a name without one reads, for a store whose secrets are all sets of keys (HashiCorp
     * Vault's KV); null - the default - when such a name reads the secret's whole value.
     */
    protected String defaultKey() {
        return null;
    }

    /** Whether the secret store can hold a secret named name; a name it can't is never fetched. */
    protected abstract boolean isValidName(String name);

    /**
     * Reads the one secret named name and hands its current value, and any keys it holds, to
     * {@code value}, or returns without doing so if it doesn't exist. Any other failure should
     * throw. Called only for a name {@link #isValidName} accepts, and never while another fetch of
     * the same secret is running.
     */
    protected abstract void fetch(String name, SecretValueSink value);

    /**
     * {@link #fetch} without blocking the caller, for decryptAsync and findMaxDecryptedLengthAsync.
     * The default implementation calls fetch on a new virtual thread, which cancelling the returned
     * future interrupts; a store with an asynchronous client overrides it. Cancelling the returned
     * future should cancel the read: anything handed to {@code value} after it has completed is
     * refused.
     *
     * @return completes once the secret has been read, or fails as fetch would throw
     */
    protected CompletableFuture<Void> fetchAsync(String name, SecretValueSink value) {
        var fetched = new CompletableFuture<Void>();
        var thread = Thread.ofVirtual().name("hkdfguard-secret-fetch").unstarted(() -> {
            try {
                fetch(name, value);
                fetched.complete(null);
            } catch (Throwable e) {
                fetched.completeExceptionally(e);
            }
        });
        fetched.whenComplete((ignored, error) -> {
            if (fetched.isCancelled())
                thread.interrupt();
        });
        thread.start();
        return fetched;
    }

    /**
     * Whether key can follow {@link #KEY_SEPARATOR} in a name: 1-{@link #MAX_KEY_LENGTH} printable
     * ASCII characters other than space, '!' and '#'.
     */
    public static boolean isValidKey(String key) {
        if (key == null || key.isEmpty() || key.length() > MAX_KEY_LENGTH)
            return false;

        for (var i = 0; i < key.length(); i++) {
            var c = key.charAt(i);
            if (c <= ' ' || c > '~' || c == UPPER_CASE_MARKER || c == KEY_SEPARATOR)
                return false;
        }
        return true;
    }

    /** @throws NullPointerException name is null */
    @Override
    public int decrypt(String name, byte[] result) {
        var entryName = entryNameFor(name);
        return entryName == null ? 0 : store.decrypt(entryName, result);
    }

    /** @throws NullPointerException name is null */
    @Override
    public int decrypt(String name, char[] result) {
        var entryName = entryNameFor(name);
        return entryName == null ? 0 : store.decrypt(entryName, result);
    }

    /** @throws NullPointerException name is null */
    @Override
    public OptionalInt findMaxDecryptedLength(String name) {
        var entryName = entryNameFor(name);
        return entryName == null ? OptionalInt.empty() : store.findMaxDecryptedLength(entryName);
    }

    /** Fails with NullPointerException when name is null. */
    @Override
    public CompletableFuture<Integer> decryptAsync(String name, byte[] result) {
        try {
            var entryName = entryNameFor(name);
            return entryName == null ? CompletableFuture.completedFuture(0) : store.decryptAsync(entryName, result);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /** Fails with NullPointerException when name is null. */
    @Override
    public CompletableFuture<Integer> decryptAsync(String name, char[] result) {
        try {
            var entryName = entryNameFor(name);
            return entryName == null ? CompletableFuture.completedFuture(0) : store.decryptAsync(entryName, result);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /** Fails with NullPointerException when name is null. */
    @Override
    public CompletableFuture<OptionalInt> findMaxDecryptedLengthAsync(String name) {
        try {
            var entryName = entryNameFor(name);
            return entryName == null
                    ? CompletableFuture.completedFuture(OptionalInt.empty())
                    : store.findMaxDecryptedLengthAsync(entryName);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * The case-escaped spelling of a name or key: each upper-case ASCII letter becomes '!' and its
     * lower-case form, so the result holds no upper-case letters and matching it ignoring ASCII
     * case is matching it exactly. "prod/Db" is "prod/!db"; "prod/db" stays as it is.
     */
    static String entryName(String secretName) {
        var builder = new StringBuilder(secretName.length() + 8);
        for (var i = 0; i < secretName.length(); i++) {
            var c = secretName.charAt(i);
            if (c >= 'A' && c <= 'Z')
                builder.append(UPPER_CASE_MARKER).append((char) (c + ('a' - 'A')));
            else
                builder.append(c);
        }
        return builder.toString();
    }

    /** The secret name {@link #entryName} made {@code entryName} from. */
    static String secretName(String entryName) {
        var builder = new StringBuilder(entryName.length());
        for (var i = 0; i < entryName.length(); i++) {
            if (entryName.charAt(i) == UPPER_CASE_MARKER)
                builder.append((char) (entryName.charAt(++i) - ('a' - 'A')));
            else
                builder.append(entryName.charAt(i));
        }
        return builder.toString();
    }

    // The entry a name is stored under - its secret's entry name, then '#' and the case-escaped key,
    // if any - or null if the name is missing without a fetch.
    private String entryNameFor(String name) {
        Objects.requireNonNull(name, "name");

        var separator = name.indexOf(KEY_SEPARATOR);
        var secretName = separator < 0 ? name : name.substring(0, separator);
        var key = separator < 0 ? defaultKey() : name.substring(separator + 1);
        if ((key != null && !isValidKey(key))
                || !isValidName(secretName)
                || (matching == SecretNameMatching.EXACT && secretName.indexOf(UPPER_CASE_MARKER) >= 0))
            return null;

        var secretEntryName = matching == SecretNameMatching.EXACT ? entryName(secretName) : secretName;
        return key == null ? secretEntryName : secretEntryName + KEY_SEPARATOR + entryName(key);
    }

    private String secretNameOf(String secretEntryName) {
        return matching == SecretNameMatching.EXACT ? secretName(secretEntryName) : secretEntryName;
    }

    // Fetches the secret stored under secretEntryName through fetch, caching everything handed
    // over; false if nothing was.
    private boolean populate(String secretEntryName) {
        var secretName = secretNameOf(secretEntryName);
        try (var op = HkdfGuardTelemetry.CACHE.startSpan(SpanNames.Cache.POPULATE)) {
            logPopulate(op.span(), secretName);
            var sink = new SecretValueSink(store, secretEntryName);
            try {
                fetch(secretName, sink);
                return cache(sink);
            } catch (RuntimeException | Error e) {
                fail(sink, op.span(), e);
                throw e;
            }
        }
    }

    // populate through fetchAsync. Its failure is wrapped in a CompletionException, so a fetch's
    // own CancellationException fails the lookup rather than reading as the caller's cancellation;
    // cancelling the result cancels the fetch.
    private CompletableFuture<Boolean> populateAsync(String secretEntryName) {
        var secretName = secretNameOf(secretEntryName);
        var span = HkdfGuardTelemetry.CACHE.getTracer().spanBuilder(SpanNames.Cache.POPULATE).startSpan();
        logPopulate(span, secretName);
        var sink = new SecretValueSink(store, secretEntryName);

        CompletableFuture<Void> fetched;
        try {
            fetched = Objects.requireNonNull(fetchAsync(secretName, sink), "fetchAsync returned null");
        } catch (RuntimeException | Error e) {
            fetched = CompletableFuture.failedFuture(e);
        }

        var populated = new CompletableFuture<Boolean>();
        fetched.whenComplete((ignored, error) -> {
            try {
                if (error != null) {
                    var cause = KeyWrapperFutures.unwrap(error);
                    fail(sink, span, cause);
                    populated.completeExceptionally(new CompletionException(cause));
                } else {
                    populated.complete(cache(sink));
                }
            } catch (RuntimeException | Error e) {
                populated.completeExceptionally(new CompletionException(e));
            } finally {
                span.end();
            }
        });
        return KeyWrapperFutures.cancelling(populated, fetched);
    }

    private void logPopulate(Span span, String secretName) {
        var telemetry = HkdfGuardTelemetry.CACHE;
        if (!telemetry.isSensitiveLoggingEnabled())
            return;

        telemetry.logSensitiveOperation(span, SpanNames.Cache.POPULATE, Attributes.of(NAME, secretName));
        HkdfGuardLog.sensitiveOperationLogged(logger, SpanNames.Cache.POPULATE, secretName);
    }

    // Closes the sink and caches what it holds; false if it holds nothing.
    private boolean cache(SecretValueSink sink) {
        var values = sink.close();
        if (values.isEmpty()) {
            recordOperation("not_found");
            return false;
        }

        // A fetch that began just after another finished may find values already stored; keep those.
        values.forEach(store::add);
        recordOperation("success");
        return true;
    }

    private void fail(SecretValueSink sink, Span span, Throwable e) {
        sink.close();
        ComponentTelemetry.recordException(span, e);
        HkdfGuardLog.operationFailed(logger, SpanNames.Cache.POPULATE, e);
        recordOperation("error");
    }

    private static void recordOperation(String result) {
        CacheMetrics.operations().add(1, Attributes.of(OPERATION_NAME, SpanNames.Cache.POPULATE, RESULT, result));
    }

    // A failure rethrown on the thread that waited for it.
    private static RuntimeException propagate(Throwable failure) {
        var cause = KeyWrapperFutures.unwrap(failure);
        if (cause instanceof RuntimeException runtime)
            return runtime;
        if (cause instanceof Error error)
            throw error;
        return new CompletionException(cause);
    }

    /** The entries, keyed by entry name, and the fetches filling them. */
    static final class Store extends ProtectedCacheBase {
        private final RemoteSecretCache owner;

        // One fetch per uncached secret at a time, whichever of its names was asked for and however;
        // removed once it completes, whatever the outcome.
        private final ConcurrentHashMap<String, CompletableFuture<Boolean>> fetches = new ConcurrentHashMap<>();

        Store(RemoteSecretCache owner, KeyRing keyRing) {
            super(keyRing);
            this.owner = owner;
        }

        KeyTrackingValue encryptEntry(String entryName, byte[] plaintext) {
            return encrypt(entryName, plaintext);
        }

        void add(String entryName, KeyTrackingValue value) {
            putEntryIfAbsent(entryName, value);
        }

        // Fetches the secret name belongs to, or waits for the fetch already running;
        // ProtectedCacheBase then looks name up again.
        @Override
        protected boolean tryPopulate(String name) {
            var secretEntryName = secretEntryNameOf(name);
            while (true) {
                var fetch = new CompletableFuture<Boolean>();
                var running = fetches.putIfAbsent(secretEntryName, fetch);
                if (running != null) {
                    try {
                        return running.join();
                    } catch (CancellationException e) {
                        // Cancelled by the lookup that started it: fetch again.
                        fetches.remove(secretEntryName, running);
                        continue;
                    } catch (CompletionException e) {
                        throw propagate(e);
                    }
                }

                try {
                    var populated = owner.populate(secretEntryName);
                    fetches.remove(secretEntryName, fetch);
                    fetch.complete(populated);
                    return populated;
                } catch (RuntimeException | Error e) {
                    fetches.remove(secretEntryName, fetch);
                    fetch.completeExceptionally(new CompletionException(e));
                    throw e;
                }
            }
        }

        // As tryPopulate, without blocking. The lookup that starts a fetch is handed the shared
        // future itself, so cancelling it cancels the fetch; every other lookup is handed one of its
        // own, so cancelling it only stops that lookup waiting.
        @Override
        protected CompletableFuture<Boolean> tryPopulateAsync(String name) {
            var secretEntryName = secretEntryNameOf(name);
            var fetch = new CompletableFuture<Boolean>();
            var running = fetches.putIfAbsent(secretEntryName, fetch);
            if (running != null)
                return join(name, secretEntryName, running);

            var population = owner.populateAsync(secretEntryName);
            population.whenComplete((populated, error) -> {
                fetches.remove(secretEntryName, fetch);
                if (error != null)
                    fetch.completeExceptionally(error instanceof CompletionException ? error : new CompletionException(error));
                else
                    fetch.complete(populated);
            });
            fetch.whenComplete((populated, error) -> {
                if (fetch.isCancelled()) {
                    fetches.remove(secretEntryName, fetch);
                    population.cancel(true);
                }
            });
            return fetch;
        }

        private CompletableFuture<Boolean> join(String name, String secretEntryName, CompletableFuture<Boolean> running) {
            var joined = new CompletableFuture<Boolean>();
            running.whenComplete((populated, error) -> {
                if (error == null) {
                    joined.complete(populated);
                } else if (running.isCancelled()) {
                    // Cancelled by the lookup that started it: fetch again, unless this one has
                    // stopped waiting too.
                    fetches.remove(secretEntryName, running);
                    if (!joined.isDone())
                        relay(tryPopulateAsync(name), joined);
                } else {
                    joined.completeExceptionally(error);
                }
            });
            return joined;
        }

        private static void relay(CompletableFuture<Boolean> from, CompletableFuture<Boolean> to) {
            from.whenComplete((populated, error) -> {
                if (error != null)
                    to.completeExceptionally(error);
                else
                    to.complete(populated);
            });
            to.whenComplete((populated, error) -> {
                if (to.isCancelled())
                    from.cancel(true);
            });
        }

        private static String secretEntryNameOf(String name) {
            var separator = name.indexOf(KEY_SEPARATOR);
            return separator < 0 ? name : name.substring(0, separator);
        }
    }
}
