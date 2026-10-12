package io.github.runsecure.hkdfguard.cache;

import static io.github.runsecure.hkdfguard.cache.TestRings.text;
import static io.github.runsecure.hkdfguard.cache.TestRings.utf8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * With a real key ring and real AES-GCM: populate-on-miss, key rotation, and name binding - a
 * ciphertext under any name but its own fails authentication.
 */
class CacheBehaviourTest {
    private final KeyRingImpl ring = TestRings.ring();

    @AfterEach
    void closeRing() {
        ring.close();
    }

    private static String decryptString(TestRings.PopulatingCache cache, String name) {
        var result = new char[64];
        return new String(result, 0, cache.decrypt(name, result));
    }

    // --- Populate on miss -----------------------------------------------------------------------

    @Test
    void decrypt_OnAMiss_CallsTryPopulate_AndReturnsThePopulatedValue() {
        var cache = new TestRings.PopulatingCache(ring);
        cache.onTryPopulate = name -> {
            cache.seed(name, "populated value".toCharArray());
            return true;
        };

        var result = new byte[32];
        assertEquals("populated value", text(result, cache.decrypt("item", result)));
        assertEquals(1, cache.tryPopulateCallCount);
    }

    @Test
    void decrypt_WhenAlreadyCached_DoesNotCallTryPopulate() {
        var cache = new TestRings.PopulatingCache(ring);
        cache.seed("item", "already cached".toCharArray());
        cache.onTryPopulate = name -> {
            throw new IllegalStateException("should not be called");
        };

        assertEquals("already cached", decryptString(cache, "item"));
        assertEquals(0, cache.tryPopulateCallCount);
    }

    @Test
    void decrypt_WhenTryPopulateFailsOrLies_ReturnsZero() {
        var cache = new TestRings.PopulatingCache(ring);
        cache.onTryPopulate = name -> false;
        assertEquals(0, cache.decrypt("item", new byte[32]));
        assertEquals(1, cache.tryPopulateCallCount);

        cache.onTryPopulate = name -> true; // claims success, stores nothing
        assertEquals(0, cache.decrypt("item", new byte[32]));

        cache.onTryPopulate = null;
        assertEquals(0, cache.decrypt("item", new byte[32]));
    }

    @Test
    void findMaxDecryptedLength_OnAMiss_CallsTryPopulate() {
        var cache = new TestRings.PopulatingCache(ring);
        cache.onTryPopulate = name -> {
            cache.seed(name, "populated value".toCharArray());
            return true;
        };

        assertTrue(cache.findMaxDecryptedLength("item").orElseThrow() > 0);
        assertEquals(1, cache.tryPopulateCallCount);
    }

    // --- Key rotation ---------------------------------------------------------------------------

    @Test
    void valuesStoredBeforeAndAfterARotation_UseTheirOwnKeys_AndAllDecrypt() {
        var cache = new TestRings.PopulatingCache(ring);

        cache.seed("before", "stored under v1".toCharArray());
        ring.add(2, TestRings.newKey()); // what scheduled ephemeral rotation does
        cache.seed("after", "stored under v2".toCharArray());

        assertEquals(1, cache.versionOf("before"));
        assertEquals(2, cache.versionOf("after"));
        assertEquals("stored under v1", decryptString(cache, "before"));
        assertEquals("stored under v2", decryptString(cache, "after"));
    }

    @Test
    void addOrUpdate_AfterARotation_ReEncryptsUnderTheNewKey() {
        var cache = new ProtectedCacheImpl(ring);
        cache.addOrUpdate("item", utf8("first"));

        ring.add(2, TestRings.newKey());
        cache.addOrUpdate("item", utf8("second"));

        var result = new byte[16];
        assertEquals("second", text(result, cache.decrypt("item", result)));
    }

    @Test
    void anEntryWhoseVersionWasSwapped_FailsAuthentication() {
        ring.add(2, TestRings.newKey());
        var cache = new TestRings.PopulatingCache(ring);
        cache.seed("item", "value".toCharArray());

        cache.relabelVersion("item", 1); // claims v1, but was encrypted under v2

        assertThrows(AuthenticationTagMismatchException.class, () -> cache.decrypt("item", new byte[16]));
    }

    // --- Name binding ---------------------------------------------------------------------------

    @Test
    void aCiphertextCopiedUnderAnotherName_FailsAuthentication_ThroughBothOverloads() {
        var cache = new TestRings.PopulatingCache(ring);
        cache.seed("ConnectionStrings:Admin", "admin-password".toCharArray());
        cache.seed("ConnectionStrings:Reporting", "reporting-password".toCharArray());

        cache.copyEntry("ConnectionStrings:Admin", "ConnectionStrings:Reporting");

        assertThrows(AuthenticationTagMismatchException.class, () -> cache.decrypt("ConnectionStrings:Reporting", new byte[64]));
        assertThrows(AuthenticationTagMismatchException.class, () -> cache.decrypt("ConnectionStrings:Reporting", new char[64]));
        // The original entry still decrypts, under any ASCII-case spelling.
        var result = new byte[64];
        assertEquals("admin-password", text(result, cache.decrypt("connectionstrings:ADMIN", result)));
    }
}
