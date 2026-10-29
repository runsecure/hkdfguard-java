package io.github.runsecure.hkdfguard.cache;

import static io.github.runsecure.hkdfguard.cache.TestRings.text;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.event.Level;

/** RemoteSecretCache's fetch-on-miss, name matching and SecretValueSink, over a fake store. */
class RemoteSecretCacheTest {
    private final KeyRingImpl ring = TestRings.ring();

    @AfterEach
    void closeRing() {
        ring.close();
    }

    private FakeRemoteSecretCache create() {
        return create(SecretNameMatching.EXACT);
    }

    private FakeRemoteSecretCache create(SecretNameMatching matching) {
        return new FakeRemoteSecretCache(ring, matching);
    }

    static String decryptString(RemoteSecretCache cache, String name) {
        var result = new char[64];
        return new String(result, 0, cache.decrypt(name, result));
    }

    // Thrown by a fetch: an unchecked failure, as a client's would be.
    static final class Unreachable extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Unreachable(String message) {
            super(message);
        }
    }

    @Test
    void aMiss_FetchesOnce_ThenEveryOverloadIsServedFromTheCache() {
        var cache = create();
        cache.set("item", "value");

        assertTrue(cache.findMaxDecryptedLength("item").orElseThrow() >= 5);
        assertEquals("value", decryptString(cache, "item"));
        var bytes = new byte[16];
        assertEquals("value", text(bytes, cache.decrypt("item", bytes)));

        assertEquals(List.of("item"), List.copyOf(cache.fetches));
    }

    @Test
    void ignoreAsciiCase_SpellingsDifferingInCase_ShareOneEntryAndOneFetch() {
        var cache = create(SecretNameMatching.IGNORE_ASCII_CASE);
        cache.set("Db-Password", "value");

        assertEquals("value", decryptString(cache, "db-password"));
        assertEquals("value", decryptString(cache, "DB-PASSWORD"));
        assertEquals(List.of("db-password"), List.copyOf(cache.fetches));
    }

    @Test
    void exact_SpellingsDifferingInCase_AreSeparateEntries_FetchedByTheirOwnSpelling() {
        var cache = create();
        cache.set("prod/Db", "upper");
        cache.set("prod/db", "lower");

        assertEquals("upper", decryptString(cache, "prod/Db"));
        assertEquals("lower", decryptString(cache, "prod/db"));
        assertEquals(0, cache.decrypt("PROD/DB", new byte[16]));
        assertEquals("upper", decryptString(cache, "prod/Db"));

        assertEquals(List.of("prod/Db", "prod/db", "PROD/DB"), List.copyOf(cache.fetches));
    }

    @Test
    void exact_ANameHoldingTheCaseMarker_IsMissing_WithoutAFetch() {
        var cache = create();

        assertEquals(0, cache.decrypt("prod/!db", new byte[16]));
        assertTrue(cache.fetches.isEmpty());
    }

    @Test
    void ignoreAsciiCase_ANameHoldingTheCaseMarker_IsFetchedLikeAnyOther() {
        var cache = create(SecretNameMatching.IGNORE_ASCII_CASE);
        cache.set("bang!", "value");

        assertEquals("value", decryptString(cache, "bang!"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"prod/Db", "ALLCAPS", "a/B_c+D=e.F@g-H", "nocaps"})
    void entryName_RoundTrips_AndHoldsNoUpperCase(String name) {
        var entry = RemoteSecretCache.entryName(name);

        assertTrue(entry.chars().noneMatch(c -> c >= 'A' && c <= 'Z'));
        assertEquals(name, RemoteSecretCache.secretName(entry));
    }

    @Test
    void anInvalidName_IsMissing_WithoutAFetch() {
        var cache = create();

        assertEquals(0, cache.decrypt("Connection:Strings", new byte[16]));
        assertEquals(0, cache.decrypt("Connection:Strings", new char[16]));
        assertTrue(cache.findMaxDecryptedLength("Connection:Strings").isEmpty());
        assertTrue(cache.fetches.isEmpty());
    }

    @Test
    void aNullName_Throws() {
        var cache = create();

        assertThrows(NullPointerException.class, () -> cache.decrypt(null, new byte[16]));
        assertThrows(NullPointerException.class, () -> cache.decrypt(null, new char[16]));
        assertThrows(NullPointerException.class, () -> cache.findMaxDecryptedLength(null));
    }

    @Test
    void aFetchThatSetsNothing_IsMissing_AndIsFetchedAgainNextTime() {
        var cache = create();

        assertEquals(0, cache.decrypt("later", new byte[16]));
        cache.set("later", "now here");
        assertEquals("now here", decryptString(cache, "later"));
        assertEquals(2, cache.fetches.size());
    }

    @Test
    void anEmptyValue_IsMissing() {
        var cache = create();
        cache.onFetch = (name, sink) -> sink.setBytes(new byte[0]);
        assertEquals(0, cache.decrypt("empty", new byte[16]));

        cache.onFetch = (name, sink) -> sink.setText("");
        assertEquals(0, cache.decrypt("empty", new byte[16]));
    }

    @Test
    void setBytes_StoresTheBytes_AndZeroesThem() {
        var cache = create();
        var given = new byte[] {1, 2, 3};
        cache.onFetch = (name, sink) -> sink.setBytes(given);

        var result = new byte[16];
        var written = cache.decrypt("binary", result);

        assertArrayEquals(new byte[] {1, 2, 3}, Arrays.copyOf(result, written));
        assertArrayEquals(new byte[3], given);
    }

    @Test
    void setText_OfALargeValue_RoundTrips() {
        var cache = create();
        var large = "é-秘密-".repeat(1500);
        cache.set("large", large);

        var result = new char[cache.findMaxDecryptedLength("large").orElseThrow()];
        assertEquals(large, new String(result, 0, cache.decrypt("large", result)));
    }

    @Test
    void settingASecondValue_Throws_AndNothingIsCached() {
        var cache = create();
        cache.onFetch = (name, sink) -> {
            sink.setText("first");
            sink.setText("second");
        };

        assertThrows(IllegalStateException.class, () -> cache.decrypt("item", new byte[16]));

        cache.onFetch = null;
        assertEquals(0, cache.decrypt("item", new byte[16]));
    }

    @Test
    void aSinkKeptPastItsFetch_RefusesEveryValue() {
        var cache = create();
        var kept = new SecretValueSink[1];
        cache.onFetch = (name, sink) -> kept[0] = sink;
        assertEquals(0, cache.decrypt("item", new byte[16]));

        var bytes = new byte[] {9};
        assertThrows(IllegalStateException.class, () -> kept[0].setBytes(bytes));
        assertEquals(0, bytes[0]);
        assertThrows(IllegalStateException.class, () -> kept[0].setText("late"));

        cache.onFetch = (name, sink) -> {
            kept[0] = sink;
            throw new Unreachable("unreachable");
        };
        assertThrows(Unreachable.class, () -> cache.decrypt("item", new byte[16]));
        assertThrows(IllegalStateException.class, () -> kept[0].setText("late"));
    }

    @Test
    void aFetchFailure_Propagates_AndIsRetriedOnTheNextLookup() {
        var cache = create();
        cache.onFetch = (name, sink) -> {
            throw new Unreachable("unreachable");
        };

        assertThrows(Unreachable.class, () -> cache.decrypt("item", new byte[16]));

        cache.onFetch = null;
        cache.set("item", "value");
        assertEquals("value", decryptString(cache, "item"));
        assertEquals(2, cache.fetches.size());
    }

    @Test
    void aFetchThrowingAnError_PropagatesIt() {
        var cache = create();
        cache.onFetch = (name, sink) -> {
            throw new AssertionError("an error");
        };

        assertThrows(AssertionError.class, () -> cache.decrypt("item", new byte[16]));
    }

    @Test
    void concurrentMissesOnOneName_ShareOneFetch() throws Exception {
        var cache = create();
        var release = new CountDownLatch(1);
        cache.onFetch = (name, sink) -> {
            await(release);
            sink.setText("value");
        };

        var lookups = new ArrayList<CompletableFuture<String>>();
        for (var i = 0; i < 8; i++)
            lookups.add(CompletableFuture.supplyAsync(() -> decryptString(cache, "shared")));
        Futures.sleep(200);
        release.countDown();

        for (var lookup : lookups)
            assertEquals("value", lookup.get(10, TimeUnit.SECONDS));
        assertEquals(1, cache.fetches.size());
    }

    @Test
    void aWaiterOnAFailedFetch_GetsTheSameFailure() throws Exception {
        var cache = create();
        var started = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        cache.onFetch = (name, sink) -> {
            started.countDown();
            await(release);
            throw new Unreachable("shared failure");
        };

        var first = CompletableFuture.supplyAsync(() -> decryptString(cache, "shared"));
        await(started);
        var second = CompletableFuture.supplyAsync(() -> decryptString(cache, "shared"));
        Futures.sleep(100);
        release.countDown();

        assertSame(Futures.assertFailsWith(Unreachable.class, first), Futures.assertFailsWith(Unreachable.class, second));
        assertEquals(1, cache.fetches.size());
    }

    @Test
    void withSensitiveLogging_AFetchLogsTheSecretsOwnName_AndAFailureLogsAnError() {
        var logger = new RecordingLogger();
        var cache = new FakeRemoteSecretCache(ring, SecretNameMatching.EXACT, logger);
        cache.set("prod/Item", "never-logged");

        TestRings.withSensitiveLogging(() -> {
            assertEquals("never-logged", decryptString(cache, "prod/Item"));
            cache.onFetch = (name, sink) -> {
                throw new Unreachable("boom");
            };
            assertThrows(Unreachable.class, () -> cache.decrypt("other", new byte[16]));
        });

        // The secret's own spelling, not its escaped entry name.
        var entries = logger.entries();
        assertTrue(entries.stream().anyMatch(e -> e.level() == Level.DEBUG
                && e.eventId() == HkdfGuardLog.SENSITIVE_OPERATION_LOGGED && e.message().contains("prod/Item")));
        assertTrue(entries.stream().anyMatch(e -> e.level() == Level.ERROR && e.exception() instanceof Unreachable));
        assertTrue(entries.stream().noneMatch(e -> e.message().contains("never-logged")));
    }

    @Test
    void withoutSensitiveLogging_OnlyFailuresAreLogged() {
        var logger = new RecordingLogger();
        var cache = new FakeRemoteSecretCache(ring, SecretNameMatching.EXACT, logger);
        cache.set("item", "value");

        assertEquals("value", decryptString(cache, "item"));
        assertTrue(logger.entries().isEmpty());
    }

    @Test
    void withoutALogger_FetchesAndFailuresStillWork_WithSensitiveLogging() {
        var cache = create(SecretNameMatching.IGNORE_ASCII_CASE);
        cache.set("item", "value");

        TestRings.withSensitiveLogging(() -> {
            assertEquals("value", decryptString(cache, "item"));
            cache.onFetch = (name, sink) -> {
                throw new Unreachable("boom");
            };
            assertThrows(Unreachable.class, () -> cache.decrypt("other", new byte[16]));
        });
    }

    @Test
    void theConstructor_RejectsANullRingOrMatching() {
        assertThrows(NullPointerException.class, () -> new FakeRemoteSecretCache(null, SecretNameMatching.EXACT));
        assertThrows(NullPointerException.class, () -> new FakeRemoteSecretCache(ring, null));
    }

    @Test
    void aStoredValue_IsBoundToItsEntryName() {
        var cache = create();
        cache.onFetch = (name, sink) -> sink.setBytes("secret".getBytes(StandardCharsets.UTF_8));

        assertEquals("secret", decryptString(cache, "a"));
        assertFalse(cache.findMaxDecryptedLength("b#k").isPresent());
    }

    static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS))
                throw new TimeoutException("The latch was never released.");
        } catch (InterruptedException | TimeoutException e) {
            throw new IllegalStateException(e);
        }
    }
}
