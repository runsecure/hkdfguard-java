package io.github.runsecure.hkdfguard.cache;

import static io.github.runsecure.hkdfguard.cache.TestRings.text;
import static io.github.runsecure.hkdfguard.cache.TestRings.utf8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** ProtectedCacheCollectionImpl's asynchronous lookups, each source asked in order with its own decryptAsync. */
class ProtectedCacheCollectionImplAsyncTest {
    private final KeyRingImpl ring = TestRings.ring();

    @AfterEach
    void closeRing() {
        ring.close();
    }

    @Test
    void decryptAsync_ReturnsFromTheFirstSourceThatHasIt_ForBothOverloads() {
        var first = new ProtectedCacheImpl(ring);
        var second = new ProtectedCacheImpl(ring);
        first.add("item", utf8("from-first"));
        second.add("item", utf8("from-second"));
        second.add("only-second", utf8("second"));
        var collection = new ProtectedCacheCollectionImpl().add(first).add(second);

        var bytes = new byte[32];
        assertEquals("from-first", text(bytes, Futures.await(collection.decryptAsync("item", bytes))));
        var chars = new char[32];
        assertEquals("second", new String(chars, 0, Futures.await(collection.decryptAsync("only-second", chars))));
        assertTrue(Futures.await(collection.findMaxDecryptedLengthAsync("only-second")).orElseThrow() >= 6);
    }

    @Test
    void decryptAsync_WithNoSourceHoldingIt_ReturnsZero() {
        var collection = new ProtectedCacheCollectionImpl().add(new ProtectedCacheImpl(ring));

        assertEquals(0, Futures.await(collection.decryptAsync("missing", new byte[16])));
        assertEquals(0, Futures.await(collection.decryptAsync("missing", new char[16])));
        assertEquals(OptionalInt.empty(), Futures.await(collection.findMaxDecryptedLengthAsync("missing")));
        assertEquals(0, Futures.await(new ProtectedCacheCollectionImpl().decryptAsync("missing", new byte[16])));
    }

    @Test
    void decryptAsync_WhenASourceFails_Fails_ForEveryMember() {
        var collection = new ProtectedCacheCollectionImpl().add(new TestRings.ThrowingReadOnlyCache(new IllegalStateException("boom")));

        Futures.assertFailsWith(IllegalStateException.class, collection.decryptAsync("item", new byte[16]));
        Futures.assertFailsWith(IllegalStateException.class, collection.decryptAsync("item", new char[16]));
        Futures.assertFailsWith(IllegalStateException.class, collection.findMaxDecryptedLengthAsync("item"));
    }

    @Test
    void decryptAsync_WhenASourceThrowsOrReturnsNoFuture_Fails() {
        var throwing = new AsyncOnlyCache(null);
        throwing.thrown = new IllegalStateException("thrown");
        Futures.assertFailsWith(IllegalStateException.class, new ProtectedCacheCollectionImpl().add(throwing).decryptAsync("item", new byte[16]));

        Futures.assertFailsWith(NullPointerException.class, new ProtectedCacheCollectionImpl().add(new AsyncOnlyCache(null)).decryptAsync("item", new byte[16]));
    }

    @Test
    void cancellingALookup_CancelsTheSourceBeingAsked_AndAsksNoMore() {
        var pending = new CompletableFuture<Integer>();
        var later = new ProtectedCacheImpl(ring);
        later.add("item", utf8("later"));
        var collection = new ProtectedCacheCollectionImpl().add(new AsyncOnlyCache(pending)).add(later);

        var lookup = collection.decryptAsync("item", new byte[16]);
        assertTrue(lookup.cancel(true));

        assertTrue(pending.isCancelled());
    }

    @Test
    void decryptAsync_WithSensitiveLoggingEnabled_StillWorks() {
        var cache = new ProtectedCacheImpl(ring);
        cache.add("item", utf8("value"));
        var collection = new ProtectedCacheCollectionImpl().add(cache);

        TestRings.withSensitiveLogging(() -> assertEquals(5, Futures.await(collection.decryptAsync("item", new byte[16]))));
    }

    // A source whose decryptAsync returns the future given, or throws.
    private static final class AsyncOnlyCache implements ProtectedReadOnlyCache {
        private final CompletableFuture<Integer> answer;
        RuntimeException thrown;

        AsyncOnlyCache(CompletableFuture<Integer> answer) {
            this.answer = answer;
        }

        @Override
        public int decrypt(String name, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int decrypt(String name, char[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OptionalInt findMaxDecryptedLength(String name) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CompletableFuture<Integer> decryptAsync(String name, byte[] result) {
            if (thrown != null)
                throw thrown;
            return answer;
        }
    }
}
