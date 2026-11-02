package io.github.runsecure.hkdfguard.cache;

import static io.github.runsecure.hkdfguard.cache.RemoteSecretCacheTest.decryptString;
import static io.github.runsecure.hkdfguard.cache.TestRings.utf8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import java.util.Arrays;
import java.util.List;
import java.util.OptionalInt;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** RemoteSecretCache's asynchronous lookups: fetchAsync, and fetches shared between callers. */
class RemoteSecretCacheAsyncTest {
    private final KeyRingImpl ring = TestRings.ring();

    @AfterEach
    void closeRing() {
        ring.close();
    }

    private FakeRemoteSecretCache create() {
        return new FakeRemoteSecretCache(ring, SecretNameMatching.EXACT);
    }

    // A lookup's decryptAsync future, as the caller holds it, and the text it reveals.
    private record Lookup(CompletableFuture<Integer> future, char[] chars) {
        String text() {
            return new String(chars, 0, Futures.await(future));
        }
    }

    private static Lookup decryptAsync(RemoteSecretCache cache, String name) {
        var chars = new char[64];
        return new Lookup(cache.decryptAsync(name, chars), chars);
    }

    // A fetchAsync that waits for release, then hands over value; started completes once it is running.
    private record Gate(CompletableFuture<Void> started, CompletableFuture<Void> release) {
    }

    private static Gate gate(FakeRemoteSecretCache cache, String value) {
        var gate = new Gate(new CompletableFuture<>(), new CompletableFuture<>());
        cache.onFetchAsync = (name, sink) -> {
            gate.started().complete(null);
            var fetched = gate.release().thenRun(() -> sink.setText(value));
            return KeyWrapperFutures.cancelling(fetched, gate.release());
        };
        return gate;
    }

    @Test
    void aMiss_FetchesThroughFetchAsync_ThenEveryOverloadIsServedFromTheCache() {
        var cache = create();
        cache.set("item", "value");

        assertTrue(Futures.await(cache.findMaxDecryptedLengthAsync("item")).orElseThrow() >= 5);
        assertEquals("value", decryptAsync(cache, "item").text());
        var bytes = new byte[16];
        assertArrayEquals(utf8("value"), Arrays.copyOf(bytes, Futures.await(cache.decryptAsync("item", bytes))));
        assertEquals("value", decryptString(cache, "item"));

        // fetchAsync's default calls fetch.
        assertEquals(List.of("item"), List.copyOf(cache.asyncFetches));
        assertEquals(List.of("item"), List.copyOf(cache.fetches));
    }

    @Test
    void theDefaultFetchAsync_RunsFetchOnAVirtualThread() {
        var cache = create();
        var thread = new Thread[1];
        cache.onFetch = (name, sink) -> {
            thread[0] = Thread.currentThread();
            sink.setText("value");
        };

        assertEquals("value", decryptAsync(cache, "item").text());
        assertTrue(thread[0].isVirtual());
    }

    @Test
    void cancellingALookup_InterruptsTheDefaultFetchAsyncsThread() {
        var cache = create();
        var started = new CountDownLatch(1);
        var interrupted = new CompletableFuture<Boolean>();
        cache.onFetch = (name, sink) -> {
            started.countDown();
            try {
                Thread.sleep(10_000);
                interrupted.complete(false);
            } catch (InterruptedException e) {
                interrupted.complete(true);
            }
        };

        var lookup = decryptAsync(cache, "item");
        RemoteSecretCacheTest.await(started);
        assertTrue(lookup.future().cancel(true));

        assertTrue(Futures.await(interrupted));
    }

    @Test
    void anOverriddenFetchAsync_IsUsed_AndFetchIsNot() {
        var cache = create();
        cache.onFetchAsync = (name, sink) -> CompletableFuture.runAsync(() -> sink.setText("async " + name));

        assertEquals("async item", decryptAsync(cache, "item").text());
        assertTrue(cache.fetches.isEmpty());
    }

    @Test
    void keysHandedOverAsynchronously_AreCachedFromOneFetch() {
        var cache = create();
        cache.onFetchAsync = (name, sink) -> CompletableFuture.runAsync(() -> sink.setBytesWithJsonKeys(utf8("{\"user\":\"app\",\"pass\":\"s3cret\"}")));

        assertEquals("s3cret", decryptAsync(cache, "db#pass").text());
        assertEquals("app", decryptAsync(cache, "db#user").text());
        assertEquals(1, cache.asyncFetches.size());
    }

    @Test
    void aMissingSecret_ReturnsZero_AndIsFetchedAgain() {
        var cache = create();

        assertEquals(0, Futures.await(cache.decryptAsync("later", new byte[16])));
        assertEquals(OptionalInt.empty(), Futures.await(cache.findMaxDecryptedLengthAsync("later")));
        cache.set("later", "now here");
        assertEquals("now here", decryptAsync(cache, "later").text());
        assertEquals(3, cache.asyncFetches.size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"in:valid", "s#bad key", "#key"})
    void anInvalidName_IsMissing_WithoutAFetch(String name) {
        var cache = create();

        assertEquals(0, Futures.await(cache.decryptAsync(name, new byte[16])));
        assertEquals(0, Futures.await(cache.decryptAsync(name, new char[16])));
        assertEquals(OptionalInt.empty(), Futures.await(cache.findMaxDecryptedLengthAsync(name)));
        assertTrue(cache.asyncFetches.isEmpty());
    }

    @Test
    void aNullName_Fails() {
        var cache = create();

        Futures.assertFailsWith(NullPointerException.class, cache.decryptAsync(null, new byte[16]));
        Futures.assertFailsWith(NullPointerException.class, cache.decryptAsync(null, new char[16]));
        Futures.assertFailsWith(NullPointerException.class, cache.findMaxDecryptedLengthAsync(null));
    }

    @Test
    void aFetchFailure_Propagates_AndIsRetriedOnTheNextLookup() {
        var cache = create();
        cache.onFetchAsync = (name, sink) -> CompletableFuture.runAsync(() -> {
            throw new RemoteSecretCacheTest.Unreachable("unreachable");
        });

        Futures.assertFailsWith(RemoteSecretCacheTest.Unreachable.class, decryptAsync(cache, "item").future());

        cache.onFetchAsync = null;
        cache.set("item", "value");
        assertEquals("value", decryptAsync(cache, "item").text());
    }

    @Test
    void aFetchAsyncThatThrowsOrReturnsNull_FailsTheLookup() {
        var cache = create();
        cache.onFetchAsync = (name, sink) -> {
            throw new RemoteSecretCacheTest.Unreachable("thrown");
        };
        Futures.assertFailsWith(RemoteSecretCacheTest.Unreachable.class, decryptAsync(cache, "item").future());

        cache.onFetchAsync = (name, sink) -> null;
        Futures.assertFailsWith(NullPointerException.class, decryptAsync(cache, "item").future());
    }

    @Test
    void aFetchsOwnCancellation_IsAFailure_NotTheCallersCancellation() {
        var cache = create();
        cache.onFetchAsync = (name, sink) -> CompletableFuture.failedFuture(new CancellationException("A timeout inside the fetch."));

        var lookup = decryptAsync(cache, "item");
        var e = Futures.assertFailsWith(CancellationException.class, lookup.future());

        assertEquals("A timeout inside the fetch.", e.getMessage());
        assertFalse(lookup.future().isCancelled());
    }

    @Test
    void aSynchronousWaiterOnAFetchCancellingItself_GetsThatFailure() {
        var cache = create();
        var gate = new CompletableFuture<Void>();
        var started = new CompletableFuture<Void>();
        cache.onFetchAsync = (name, sink) -> {
            started.complete(null);
            return gate.thenRun(() -> {
                throw new CancellationException("A timeout inside the fetch.");
            });
        };

        var owner = decryptAsync(cache, "shared");
        Futures.await(started);
        var waiter = CompletableFuture.supplyAsync(() -> decryptString(cache, "shared"));
        Futures.sleep(100);
        gate.complete(null);

        Futures.assertFailsWith(CancellationException.class, owner.future());
        Futures.assertFailsWith(CancellationException.class, waiter);
        assertEquals(1, cache.asyncFetches.size());
    }

    @Test
    void concurrentSyncAndAsyncLookups_ShareOneFetch() throws Exception {
        var cache = create();
        var gate = gate(cache, "value");

        var first = decryptAsync(cache, "shared");
        Futures.await(gate.started());
        var second = decryptAsync(cache, "shared");
        var third = CompletableFuture.supplyAsync(() -> decryptString(cache, "shared"));
        var fourth = CompletableFuture.supplyAsync(() -> decryptString(cache, "shared"));
        Futures.sleep(100);
        gate.release().complete(null);

        assertEquals("value", first.text());
        assertEquals("value", second.text());
        assertEquals("value", third.get(10, TimeUnit.SECONDS));
        assertEquals("value", fourth.get(10, TimeUnit.SECONDS));
        assertEquals(1, cache.asyncFetches.size());
        assertTrue(cache.fetches.isEmpty());
    }

    @Test
    void aSyncLookupStartingTheFetch_IsJoinedByAsyncOnes() throws Exception {
        var cache = create();
        var release = new CountDownLatch(1);
        cache.onFetch = (name, sink) -> {
            RemoteSecretCacheTest.await(release);
            sink.setText("value");
        };

        var sync = CompletableFuture.supplyAsync(() -> decryptString(cache, "shared"));
        while (cache.fetches.isEmpty())
            Futures.sleep(10);
        var asynchronous = decryptAsync(cache, "shared");
        Futures.sleep(100);
        release.countDown();

        assertEquals("value", sync.get(10, TimeUnit.SECONDS));
        assertEquals("value", asynchronous.text());
        assertEquals(1, cache.fetches.size());
        assertTrue(cache.asyncFetches.isEmpty());
    }

    @Test
    void anAsyncJoinerOfAFailedFetch_GetsTheFailure() {
        var cache = create();
        var gate = new CompletableFuture<Void>();
        cache.onFetchAsync = (name, sink) -> gate.thenRun(() -> {
            throw new RemoteSecretCacheTest.Unreachable("shared failure");
        });

        var owner = decryptAsync(cache, "shared");
        var joiner = decryptAsync(cache, "shared");
        gate.complete(null);

        Futures.assertFailsWith(RemoteSecretCacheTest.Unreachable.class, owner.future());
        Futures.assertFailsWith(RemoteSecretCacheTest.Unreachable.class, joiner.future());
        assertEquals(1, cache.asyncFetches.size());
    }

    @Test
    void aJoinerCancellingItsWait_LeavesTheFetchRunningForTheOthers() {
        var cache = create();
        var gate = gate(cache, "value");

        var owner = decryptAsync(cache, "shared");
        Futures.await(gate.started());
        var joiner = decryptAsync(cache, "shared");
        Futures.sleep(50);
        assertTrue(joiner.future().cancel(true));

        assertThrows(CancellationException.class, () -> joiner.future().join());
        gate.release().complete(null);
        assertEquals("value", owner.text());
        assertEquals(1, cache.asyncFetches.size());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void whenTheLookupThatStartedAFetchCancelsIt_AJoinerFetchesAgain(boolean synchronousJoiner) throws Exception {
        var cache = create();
        var gate = gate(cache, "never");

        var owner = decryptAsync(cache, "shared");
        Futures.await(gate.started());
        CompletableFuture<String> joiner = synchronousJoiner
                ? CompletableFuture.supplyAsync(() -> decryptString(cache, "shared"))
                : CompletableFuture.supplyAsync(() -> decryptAsync(cache, "shared").text());
        Futures.sleep(100);

        // The fetch the joiner starts once the first is cancelled answers at once.
        cache.onFetchAsync = (name, sink) -> {
            sink.setText("second fetch");
            return CompletableFuture.completedFuture(null);
        };
        cache.onFetch = (name, sink) -> sink.setText("second fetch");
        assertTrue(owner.future().cancel(true));

        assertThrows(CancellationException.class, () -> owner.future().join());
        assertEquals("second fetch", joiner.get(10, TimeUnit.SECONDS));
    }

    @Test
    void aSinkUsedAfterItsFetchWasCancelled_RefusesTheValue() {
        var cache = create();
        var kept = new CompletableFuture<SecretValueSink>();
        cache.onFetchAsync = (name, sink) -> {
            kept.complete(sink);
            return new CompletableFuture<>();
        };

        var lookup = decryptAsync(cache, "item");
        var sink = Futures.await(kept);
        assertTrue(lookup.future().cancel(true));

        assertThrows(IllegalStateException.class, () -> sink.setText("late"));
        cache.onFetchAsync = null;
        assertEquals(0, Futures.await(cache.decryptAsync("item", new byte[16])));
    }

    @Test
    void inACollection_ARemoteSourceIsAskedAsynchronously() {
        var remote = create();
        remote.onFetchAsync = (name, sink) -> CompletableFuture.runAsync(() -> sink.setText("remote value"));
        var local = new ProtectedCacheImpl(ring);
        local.add("local", utf8("local value"));
        var collection = new ProtectedCacheCollectionImpl().add(local).add(remote);

        var chars = new char[32];
        assertEquals("local value", new String(chars, 0, Futures.await(collection.decryptAsync("local", chars))));
        assertEquals("remote value", new String(chars, 0, Futures.await(collection.decryptAsync("remote", chars))));
        assertEquals(List.of("remote"), List.copyOf(remote.asyncFetches));
        assertTrue(remote.fetches.isEmpty());
        assertTrue(Futures.await(collection.findMaxDecryptedLengthAsync("remote")).orElseThrow() >= "remote value".length());
        assertTrue(Futures.await(collection.findMaxDecryptedLengthAsync("local")).orElseThrow() >= "local value".length());
        assertEquals(OptionalInt.empty(), Futures.await(collection.findMaxDecryptedLengthAsync("in:valid")));
    }

    @Test
    void inACollection_CancellingALookup_CancelsTheRemoteFetch() {
        var remote = create();
        var gate = gate(remote, "value");
        var collection = new ProtectedCacheCollectionImpl().add(remote);

        var lookup = collection.decryptAsync("item", new char[16]);
        Futures.await(gate.started());
        assertTrue(lookup.cancel(true));

        assertTrue(gate.release().isCancelled());
    }
}
