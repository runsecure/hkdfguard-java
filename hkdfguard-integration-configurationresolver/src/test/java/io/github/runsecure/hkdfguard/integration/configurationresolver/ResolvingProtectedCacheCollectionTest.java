package io.github.runsecure.hkdfguard.integration.configurationresolver;

import static io.github.runsecure.hkdfguard.integration.configurationresolver.TestSources.bytes;
import static io.github.runsecure.hkdfguard.integration.configurationresolver.TestSources.chars;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.integration.configurationresolver.TestSources.MapValueProvider;
import io.github.runsecure.hkdfguard.integration.configurationresolver.TestSources.PlainSource;
import io.github.runsecure.hkdfguard.integration.configurationresolver.TestSources.RemoteSource;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ResolvingProtectedCacheCollectionTest {
    private static final String RESOLVED = "Host=db.internal;Password=s3cret";

    private final KeyRingImpl ring = TestSources.ring();
    private final PlainSource source = new PlainSource()
            .with("conn", "Host=${host};Password=${password}")
            .with("host", "db.internal")
            .with("password", "s3cret");
    private final ResolvingProtectedCacheCollection collection = new ResolvingProtectedCacheCollection(ring).add(source);

    @AfterEach
    void closeRing() {
        ring.close();
    }

    private static Throwable failure(Supplier<? extends CompletableFuture<?>> lookup) {
        return assertThrows(CompletionException.class, () -> lookup.get().join()).getCause();
    }

    @Test
    void template_IsResolvedFromTheSources_AndCached() {
        assertEquals(RESOLVED, chars(collection, "conn"));
        assertEquals(RESOLVED, bytes(collection, "conn"));

        // Read and resolved once; every later lookup decrypts the cached result.
        assertEquals(1, source.decryptCount("conn"));
        assertEquals(1, source.decryptCount("password"));
    }

    @Test
    void template_IsResolvedByAFirstDecrypt_WithoutSizingFirst() {
        var asyncCollection = new ResolvingProtectedCacheCollection(ring).add(source);

        var result = new byte[64];
        assertEquals(RESOLVED, new String(result, 0, collection.decrypt("conn", result), StandardCharsets.UTF_8));
        assertEquals(RESOLVED, new String(result, 0, asyncCollection.decryptAsync("conn", result).join(), StandardCharsets.UTF_8));
    }

    @Test
    void resolvedValue_IsCachedEncrypted_NotAsTheSourcesValues() {
        // An AEAD bound: longer than the resolved value it encloses.
        assertTrue(collection.findMaxDecryptedLength("conn").orElseThrow() > RESOLVED.length());
    }

    @Test
    void valueWithoutItems_IsAnsweredByItsSource_WhichIsRemembered() {
        assertEquals("s3cret", chars(collection, "password"));
        assertEquals("s3cret", bytes(collection, "password"));

        // One search through the sources, then only the two findMaxDecryptedLength calls the
        // remembered source answers.
        assertEquals(3, source.lengthLookupCount("password"));
        assertEquals(3, source.decryptCount("password"));
    }

    @Test
    void missingName_IsReportedMissing() {
        assertEquals(0, collection.decrypt("absent", new byte[16]));
        assertEquals(0, collection.decrypt("absent", new char[16]));
        assertEquals(OptionalInt.empty(), collection.findMaxDecryptedLength("absent"));
        assertEquals(0, collection.decryptAsync("absent", new byte[16]).join());
        assertEquals(0, collection.decryptAsync("absent", new char[16]).join());
        assertEquals(OptionalInt.empty(), collection.findMaxDecryptedLengthAsync("absent").join());
    }

    @Test
    void sources_AreCheckedInOrder_ForNamesAndItems() {
        var first = new PlainSource().with("conn", "${password}").with("password", "first");
        var second = new PlainSource().with("conn", "ignored").with("password", "second").with("only-second", "${password}");
        var ordered = new ResolvingProtectedCacheCollection(ring).add(first).add(second);

        assertEquals("first", chars(ordered, "conn"));
        assertEquals("first", chars(ordered, "only-second"));
        assertEquals(0, second.decryptCount("conn"));
    }

    @Test
    void valueProviders_SupplyItemsAfterTheSources_GrowingTheBufferWhenNeeded() {
        var large = "x".repeat(5000);
        var mixed = new ResolvingProtectedCacheCollection(ring)
                .add(new PlainSource().with("conn", "Host=${host};Blob=${blob}").with("host", "from-source"))
                .addValueProvider(new MapValueProvider(Map.of("host", "ignored", "blob", large)));

        assertEquals("Host=from-source;Blob=" + large, chars(mixed, "conn"));
    }

    @Test
    void valueProviders_AreNotAnsweredByNameOnTheirOwn() {
        var providerOnly = new ResolvingProtectedCacheCollection(ring).addValueProvider(new MapValueProvider(Map.of("host", "db")));

        assertEquals(OptionalInt.empty(), providerOnly.findMaxDecryptedLength("host"));
    }

    @Test
    void items_AreResolvedOneLevelDeep_AndEscapesApply() {
        var nested = new ResolvingProtectedCacheCollection(ring).add(new PlainSource()
                .with("nested", "url=${url}")
                .with("url", "jdbc://${host}/orders")
                .with("escaped", "literal $${host} and ${host}")
                .with("host", "db.internal"));

        // An item whose value is a template inserts that template's text unresolved.
        assertEquals("url=jdbc://${host}/orders", chars(nested, "nested"));
        assertEquals("literal ${host} and db.internal", chars(nested, "escaped"));
    }

    @Test
    void customToken_IsUsed() {
        var token = new ConfigurationItemTokenBase("#{", "}", null) {
        };
        var custom = new ResolvingProtectedCacheCollection(ring, token, 64)
                .add(new PlainSource().with("conn", "#{host} ${host}").with("host", "db"));

        assertSame(token, custom.token());
        assertEquals(64, custom.maxResolvedLength());
        assertEquals("db ${host}", chars(custom, "conn"));
    }

    @Test
    void resolvedValueLongerThanMaxResolvedLength_Throws() {
        var limited = new ResolvingProtectedCacheCollection(ring, new DefaultToken(), 16)
                .add(new PlainSource().with("conn", "${blob}"))
                .addValueProvider(new MapValueProvider(Map.of("blob", "x".repeat(17))));

        var error = assertThrows(IllegalStateException.class, () -> limited.decrypt("conn", new char[64]));
        assertInstanceOf(DestinationTooSmallException.class, error.getCause());
        assertInstanceOf(IllegalStateException.class, failure(() -> limited.decryptAsync("conn", new char[64])));
    }

    @Test
    void maxResolvedLength_DefaultsAndRejectsLessThanOne() {
        assertEquals(ResolvingProtectedCacheCollection.DEFAULT_MAX_RESOLVED_LENGTH, collection.maxResolvedLength());
        assertInstanceOf(DefaultToken.class, collection.token());
        assertThrows(IllegalArgumentException.class, () -> new ResolvingProtectedCacheCollection(ring, new DefaultToken(), 0));
    }

    @Test
    void templateNamingAMissingValue_Throws() {
        var broken = new ResolvingProtectedCacheCollection(ring).add(new PlainSource().with("conn", "${absent}"));

        var error = assertThrows(ConfigurationKeyException.class, () -> broken.decrypt("conn", new byte[64]));
        assertEquals(ConfigurationKeyError.NOT_FOUND, error.getError());
        assertThrows(ConfigurationKeyException.class, () -> broken.decrypt("conn", new char[64]));
        assertThrows(ConfigurationKeyException.class, () -> broken.findMaxDecryptedLength("conn"));
        assertInstanceOf(ConfigurationKeyException.class, failure(() -> broken.decryptAsync("conn", new byte[64])));
        assertInstanceOf(ConfigurationKeyException.class, failure(() -> broken.decryptAsync("conn", new char[64])));
        assertInstanceOf(ConfigurationKeyException.class, failure(() -> broken.findMaxDecryptedLengthAsync("conn")));
    }

    @Test
    void templateResolvingToNothing_IsReportedMissing() {
        var empty = new ResolvingProtectedCacheCollection(ring)
                .add(new PlainSource().with("conn", "${empty}"))
                .addValueProvider(new MapValueProvider(Map.of("empty", "")));

        assertEquals(OptionalInt.empty(), empty.findMaxDecryptedLength("conn"));
        assertEquals(0, empty.decrypt("conn", new char[16]));
    }

    @Test
    void resolvedValue_IsKeptUntilInvalidated() {
        assertEquals(RESOLVED, chars(collection, "conn"));

        source.with("password", "rotated");
        assertEquals(RESOLVED, chars(collection, "conn"));

        assertTrue(collection.invalidate("conn"));
        assertEquals("Host=db.internal;Password=rotated", chars(collection, "conn"));
        assertFalse(collection.invalidate("never-looked-up"));
    }

    @Test
    void invalidate_ForgetsWhichSourceHoldsAPlainValue() {
        var first = new PlainSource();
        var second = new PlainSource().with("password", "second");
        var ordered = new ResolvingProtectedCacheCollection(ring).add(first).add(second);
        assertEquals("second", chars(ordered, "password"));

        first.with("password", "first");
        assertEquals("second", chars(ordered, "password"));

        assertTrue(ordered.invalidate("password"));
        assertEquals("first", chars(ordered, "password"));
    }

    @Test
    void clear_ForgetsEverything() {
        chars(collection, "conn");
        chars(collection, "host");

        source.with("host", "db2").with("password", "rotated");
        collection.clear();

        assertEquals("Host=db2;Password=rotated", chars(collection, "conn"));
        assertEquals("db2", chars(collection, "host"));
    }

    @Test
    void invalidateDuringAResolve_KeepsItsResultOutOfTheCache() {
        // Run as the resolver sizes the value: a real cache can't change a value between sizing and
        // decrypting it, but can between two lookups.
        source.onFirstLookup("password", () -> {
            source.with("password", "rotated");
            collection.invalidate("conn");
        });

        // The first resolution read the old value, so it is dropped and the lookup resolves again.
        var result = new char[64];
        assertEquals("Host=db.internal;Password=rotated", new String(result, 0, collection.decrypt("conn", result)));
        assertEquals(2, source.decryptCount("conn"));

        assertEquals("Host=db.internal;Password=rotated", new String(result, 0, collection.decrypt("conn", result)));
        assertEquals(2, source.decryptCount("conn"));
    }

    @Test
    void invalidateDuringAPlainLookup_DoesNotRememberTheSource() {
        source.onFirstLookup("host", collection::clear);

        assertEquals("db.internal", chars(collection, "host"));
        var lookups = source.lengthLookupCount("host");

        assertEquals("db.internal", chars(collection, "host"));
        assertEquals(lookups + 1, source.lengthLookupCount("host"));
    }

    @Test
    void names_MatchExactly_EvenWhereTheResolvedStoreIgnoresCase() {
        var cased = new ResolvingProtectedCacheCollection(ring).add(new PlainSource()
                .with("Db", "upper ${value}")
                .with("db", "lower ${value}")
                .with("a!b", "bang ${value}")
                .with("aB", "camel ${value}")
                .with("app/Db-1", "path ${value}")
                .with("value", "v"));

        assertEquals("upper v", chars(cased, "Db"));
        assertEquals("lower v", chars(cased, "db"));
        assertEquals("bang v", chars(cased, "a!b"));
        assertEquals("camel v", chars(cased, "aB"));
        assertEquals("path v", chars(cased, "app/Db-1"));
        assertEquals("upper v", chars(cased, "Db"));
    }

    @Test
    void storeKey_IsInjective_AndHasNoLowerCaseAscii() {
        var keys = new HashSet<String>();
        for (var name : new String[] {"Db", "db", "DB", "!D!B", "a!b", "A!B", "!", "!!", "", "café"}) {
            var key = ResolvingProtectedCacheCollection.storeKey(name);
            assertTrue(keys.add(key), name);
            assertTrue(key.chars().noneMatch(c -> c >= 'a' && c <= 'z'), key);
        }
        assertSame("DB-1", ResolvingProtectedCacheCollection.storeKey("DB-1"));
    }

    @Test
    void asyncLookups_ResolveFromARemoteSource_WithoutBlockingFetches() {
        var remote = new RemoteSource();
        remote.with("conn", "Host=${host};Password=${password}")
                .with("host", "db.internal")
                .with("password", "s3cret")
                .with("plain", "value");
        var remoteCollection = new ResolvingProtectedCacheCollection(ring).add(remote);

        var maxLength = remoteCollection.findMaxDecryptedLengthAsync("conn").join().orElseThrow();
        var chars = new char[maxLength];
        var bytes = new byte[maxLength];

        assertEquals(RESOLVED, new String(chars, 0, remoteCollection.decryptAsync("conn", chars).join()));
        assertEquals(RESOLVED, new String(bytes, 0, remoteCollection.decryptAsync("conn", bytes).join(), StandardCharsets.UTF_8));
        assertEquals(OptionalInt.of(maxLength), remoteCollection.findMaxDecryptedLengthAsync("conn").join());

        // A plain value, found and then remembered.
        assertTrue(remoteCollection.findMaxDecryptedLengthAsync("plain").join().isPresent());
        assertEquals("value", new String(chars, 0, remoteCollection.decryptAsync("plain", chars).join()));
        assertEquals("value", new String(bytes, 0, remoteCollection.decryptAsync("plain", bytes).join(), StandardCharsets.UTF_8));

        // Every value was fetched asynchronously.
        assertEquals(Set.of(), remote.blockingFetches);
        assertEquals(Set.of("conn", "host", "password", "plain"), remote.asyncFetches);
    }

    @Test
    void asyncLookup_AfterTheTemplateWasInvalidated_ResolvesAgain() {
        assertTrue(collection.findMaxDecryptedLengthAsync("conn").join().isPresent());

        source.with("password", "rotated");
        collection.invalidate("conn");

        var result = new char[64];
        assertEquals("Host=db.internal;Password=rotated", new String(result, 0, collection.decryptAsync("conn", result).join()));
    }

    @Test
    void realCaches_CanBeSources() {
        var secrets = new ProtectedCacheImpl(ring);
        secrets.add("db-password", "s3cret".toCharArray());
        secrets.add("conn", "Password=${db-password}".toCharArray());
        var real = new ResolvingProtectedCacheCollection(ring).add(secrets);

        assertEquals("Password=s3cret", chars(real, "conn"));
        assertEquals("s3cret", bytes(real, "db-password"));
    }

    @Test
    void sourceThatThrows_FailsTheLookup() {
        var failing = new ResolvingProtectedCacheCollection(ring).add(new ThrowingSource());

        assertThrows(IllegalStateException.class, () -> failing.decrypt("conn", new char[8]));
        assertInstanceOf(IllegalStateException.class, failure(() -> failing.decryptAsync("conn", new char[8])));
        assertInstanceOf(IllegalStateException.class, failure(() -> failing.findMaxDecryptedLengthAsync("conn")));
    }

    @Test
    void sensitiveLogging_IncludesTheName() {
        var previous = HkdfGuardTelemetry.CACHE.isSensitiveLoggingEnabled();
        HkdfGuardTelemetry.CACHE.setSensitiveLoggingEnabled(true);
        try {
            assertEquals("s3cret", chars(collection, "password"));
            assertEquals(6, collection.decryptAsync("password", new char[16]).join());
        } finally {
            HkdfGuardTelemetry.CACHE.setSensitiveLoggingEnabled(previous);
        }
    }

    @Test
    void members_RejectNullArguments() {
        assertThrows(NullPointerException.class, () -> new ResolvingProtectedCacheCollection(null));
        assertThrows(NullPointerException.class, () -> new ResolvingProtectedCacheCollection(ring, null, 1));
        assertThrows(NullPointerException.class, () -> collection.add(null));
        assertThrows(NullPointerException.class, () -> collection.addValueProvider(null));
        assertThrows(NullPointerException.class, () -> collection.invalidate(null));
        assertThrows(NullPointerException.class, () -> collection.decrypt(null, new byte[1]));
        assertThrows(NullPointerException.class, () -> collection.decrypt("conn", (char[]) null));
        assertThrows(NullPointerException.class, () -> collection.findMaxDecryptedLength(null));

        // The asynchronous members report it through their future.
        assertInstanceOf(NullPointerException.class, failure(() -> collection.decryptAsync(null, new byte[1])));
        assertInstanceOf(NullPointerException.class, failure(() -> collection.decryptAsync("conn", (char[]) null)));
        assertInstanceOf(NullPointerException.class, failure(() -> collection.findMaxDecryptedLengthAsync(null)));
    }

    private static final class ThrowingSource implements ProtectedReadOnlyCache {
        @Override
        public int decrypt(String name, byte[] result) {
            throw new IllegalStateException("unreachable");
        }

        @Override
        public int decrypt(String name, char[] result) {
            throw new IllegalStateException("unreachable");
        }

        @Override
        public OptionalInt findMaxDecryptedLength(String name) {
            throw new IllegalStateException("unreachable");
        }
    }
}
