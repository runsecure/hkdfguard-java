package io.github.runsecure.hkdfguard.cache;

import static io.github.runsecure.hkdfguard.cache.TestRings.text;
import static io.github.runsecure.hkdfguard.cache.TestRings.utf8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ProtectedCacheCollectionImplTest {
    private final KeyRingImpl firstRing = TestRings.ring();
    private final KeyRingImpl secondRing = TestRings.ring();
    private final ProtectedCacheImpl first = new ProtectedCacheImpl(firstRing);
    private final ProtectedCacheImpl second = new ProtectedCacheImpl(secondRing);

    @AfterEach
    void closeRings() {
        firstRing.close();
        secondRing.close();
    }

    @Test
    void add_ReturnsTheSameInstance_ForFluentChaining() {
        var collection = new ProtectedCacheCollectionImpl();

        assertSame(collection, collection.add(first));
    }

    @Test
    void withNoSources_EveryLookupMisses() {
        var collection = new ProtectedCacheCollectionImpl();

        assertEquals(0, collection.decrypt("item", new byte[16]));
        assertEquals(0, collection.decrypt("item", new char[16]));
        assertTrue(collection.findMaxDecryptedLength("item").isEmpty());
    }

    @Test
    void lookups_ReturnFromTheFirstSourceThatHasTheName() {
        first.add("item", utf8("from-first"));
        second.add("item", utf8("a much longer value from the second source"));
        var collection = new ProtectedCacheCollectionImpl().add(first).add(second);

        var bytes = new byte[64];
        assertEquals("from-first", text(bytes, collection.decrypt("item", bytes)));
        var chars = new char[64];
        assertEquals("from-first", new String(chars, 0, collection.decrypt("item", chars)));
        assertEquals(first.findMaxDecryptedLength("item"), collection.findMaxDecryptedLength("item"));
    }

    @Test
    void lookups_FallThroughToALaterSource_WhenEarlierOnesLackTheName() {
        second.add("item", "from-second".toCharArray());
        var collection = new ProtectedCacheCollectionImpl().add(first).add(second);

        var bytes = new byte[64];
        assertEquals("from-second", text(bytes, collection.decrypt("item", bytes)));
        var chars = new char[64];
        assertEquals("from-second", new String(chars, 0, collection.decrypt("item", chars)));
        assertTrue(collection.findMaxDecryptedLength("item").orElseThrow() > 0);
    }

    @Test
    void lookups_WithNoSourceHavingTheName_Miss() {
        var collection = new ProtectedCacheCollectionImpl().add(first).add(second);

        assertEquals(0, collection.decrypt("missing", new byte[16]));
        assertEquals(0, collection.decrypt("missing", new char[16]));
        assertTrue(collection.findMaxDecryptedLength("missing").isEmpty());
    }

    @Test
    void decrypt_WithSensitiveLoggingEnabled_StillRoundTrips() {
        TestRings.withSensitiveLogging(() -> {
            first.add("item", utf8("top secret"));
            var collection = new ProtectedCacheCollectionImpl().add(first);

            var bytes = new byte[32];
            assertEquals("top secret", text(bytes, collection.decrypt("item", bytes)));
            var chars = new char[32];
            assertEquals("top secret", new String(chars, 0, collection.decrypt("item", chars)));
        });
    }

    @Test
    void decrypt_WhenASourceThrows_Rethrows() {
        var collection = new ProtectedCacheCollectionImpl().add(new TestRings.ThrowingReadOnlyCache(new IllegalStateException("boom")));

        assertThrows(IllegalStateException.class, () -> collection.decrypt("item", new byte[16]));
        assertThrows(IllegalStateException.class, () -> collection.decrypt("item", new char[16]));
    }
}
