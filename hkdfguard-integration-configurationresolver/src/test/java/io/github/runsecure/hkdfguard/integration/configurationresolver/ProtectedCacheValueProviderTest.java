package io.github.runsecure.hkdfguard.integration.configurationresolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.integration.configurationresolver.TestSources.MapValueProvider;
import io.github.runsecure.hkdfguard.integration.configurationresolver.TestSources.RemoteSource;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ProtectedCacheValueProviderTest {
    private final KeyRingImpl ring = TestSources.ring();

    @AfterEach
    void closeRing() {
        ring.close();
    }

    private ProtectedCacheImpl cache(String... namesAndValues) {
        var cache = new ProtectedCacheImpl(ring);
        for (var i = 0; i < namesAndValues.length; i += 2)
            cache.add(namesAndValues[i], namesAndValues[i + 1].toCharArray());
        return cache;
    }

    private static ConfigurationResolver resolver(String template, ProtectedReadOnlyCache cache) {
        var token = new DefaultToken();
        var reader = new ConfigurationItemReaderImpl(token);
        reader.readKeys(template);
        return new ConfigurationItemResolver(token, reader, new ProtectedCacheValueProvider(cache));
    }

    @Test
    void resolve_Chars_ReplacesItemsWithCachedValues() {
        var secrets = cache("db-user", "app", "db-password", "s3cret");
        var template = "User=${db-user};Password=${db-password}";

        var destination = new char[256];
        var written = resolver(template, secrets).resolve(template, destination);

        assertEquals("User=app;Password=s3cret", new String(destination, 0, written));
    }

    @Test
    void resolve_Utf8_ReplacesItemsWithCachedValues() {
        var secrets = cache("db-password", "pässword");
        var template = "Password=${db-password}";

        var destination = new byte[256];
        var written = resolver(template, secrets).resolve(template.getBytes(StandardCharsets.UTF_8), destination);

        assertEquals("Password=pässword", new String(destination, 0, written, StandardCharsets.UTF_8));
    }

    @Test
    void resolve_MissingName_ThrowsNotFound() {
        var secrets = cache("present", "value");
        var template = "${absent}";

        var error = assertThrows(ConfigurationKeyException.class, () -> resolver(template, secrets).resolve(template, new char[64]));

        assertEquals(ConfigurationKeyError.NOT_FOUND, error.getError());
    }

    // The cache's bound is the ciphertext's length, so a destination with exactly the value's room is
    // below it: the value goes through the scratch array, whatever its size.
    @ParameterizedTest
    @ValueSource(ints = {5, 612})
    void resolve_Chars_DestinationBelowBoundButValueFits_Resolves(int valueLength) {
        var value = "v".repeat(valueLength);
        var template = "${item}";

        var destination = new char[valueLength];
        var written = resolver(template, cache("item", value)).resolve(template, destination);

        assertEquals(value, new String(destination, 0, written));
    }

    @ParameterizedTest
    @ValueSource(ints = {5, 612})
    void resolve_Utf8_DestinationBelowBoundButValueFits_Resolves(int valueLength) {
        var value = "v".repeat(valueLength);

        var destination = new byte[valueLength];
        var written = resolver("${item}", cache("item", value)).resolve("${item}".getBytes(StandardCharsets.UTF_8), destination);

        assertEquals(value, new String(destination, 0, written, StandardCharsets.UTF_8));
    }

    @Test
    void resolve_Chars_ValueLargerThanDestination_ThrowsAndWipesDestination() {
        var destination = new char[4];

        assertThrows(DestinationTooSmallException.class, () -> resolver("${item}", cache("item", "too long a value")).resolve("${item}", destination));

        for (var c : destination)
            assertEquals('\0', c);
    }

    @Test
    void resolve_Utf8_ValueLargerThanDestination_ThrowsAndWipesDestination() {
        var destination = new byte[4];

        assertThrows(DestinationTooSmallException.class,
                () -> resolver("${item}", cache("item", "too long a value")).resolve("${item}".getBytes(StandardCharsets.UTF_8), destination));

        for (var b : destination)
            assertEquals(0, b);
    }

    @Test
    void tryGet_WritesAtThePosition_AndMovesItPastTheValue() {
        var provider = new ProtectedCacheValueProvider(cache("item", "value"));
        var chars = CharBuffer.allocate(16).position(3);
        var bytes = ByteBuffer.allocate(16).position(3);

        assertEquals(ValueStatus.FOUND, provider.tryGetChars("item", chars));
        assertEquals(ValueStatus.FOUND, provider.tryGetBytes("item", bytes));

        assertEquals(8, chars.position());
        assertEquals("value", new String(chars.array(), 3, 5));
        assertEquals(8, bytes.position());
        assertEquals("value", new String(bytes.array(), 3, 5, StandardCharsets.UTF_8));
    }

    @Test
    void tryGet_ValueLargerThanTheRoomLeft_IsTooSmall_AndWritesNothing() {
        var provider = new ProtectedCacheValueProvider(cache("item", "value"));
        var chars = CharBuffer.allocate(4);
        var bytes = ByteBuffer.allocate(4);

        assertEquals(ValueStatus.DESTINATION_TOO_SMALL, provider.tryGetChars("item", chars));
        assertEquals(ValueStatus.DESTINATION_TOO_SMALL, provider.tryGetBytes("item", bytes));
        assertEquals(0, chars.position());
        assertEquals(0, bytes.position());
    }

    @Test
    void findValue_ByDefault_Throws() {
        var provider = new ProtectedCacheValueProvider(cache("item", "value"));

        assertFalse(provider.allowStringValues());
        assertThrows(IllegalStateException.class, () -> provider.findValue("item"));
    }

    @Test
    void findValue_WhenAllowed_ReturnsTheValueAsAString() {
        var provider = new ProtectedCacheValueProvider(cache("item", "value"), true);

        assertTrue(provider.allowStringValues());
        assertEquals(Optional.of("value"), provider.findValue("item"));
        assertEquals(Optional.empty(), provider.findValue("absent"));
    }

    @Test
    void compositeValueProvider_FallsThroughToTheNextProviderForMissingNames() {
        var secrets = cache("db-password", "s3cret");
        var plain = new MapValueProvider(Map.of("db-host", "db.internal"));
        var template = "Host=${db-host};Password=${db-password}";

        var token = new DefaultToken();
        var reader = new ConfigurationItemReaderImpl(token);
        reader.readKeys(template);
        var resolver = new ConfigurationItemResolver(token, reader, new ProtectedCacheValueProvider(secrets), plain);

        var destination = new char[256];
        var written = resolver.resolve(template, destination);

        assertEquals("Host=db.internal;Password=s3cret", new String(destination, 0, written));
    }

    @Test
    void addProtectedCache_AddsAProviderOverTheCache() {
        var secrets = cache("db-password", "s3cret");
        var template = "Password=${db-password}";
        var token = new DefaultToken();
        var reader = new ConfigurationItemReaderImpl(token);
        reader.readKeys(template);

        var builder = new ConfigurationResolverBuilderImpl().withToken(token).withReader(reader);
        var resolver = ConfigurationResolverBuilderExtensions.addProtectedCache(builder, secrets).build();

        var destination = new char[64];
        var written = resolver.resolve(template, destination);

        assertEquals("Password=s3cret", new String(destination, 0, written));
    }

    @Test
    void prefetchAsync_FetchesEachKeyOnceWithoutBlocking_SoResolveDoesNotFetch() {
        var remote = new RemoteSource();
        remote.with("app-config#user", "app").with("app-config#password", "s3cret");
        var template = "User=${app-config#user};Password=${app-config#password};Again=${app-config#user}";
        var token = new DefaultToken();
        var reader = new ConfigurationItemReaderImpl(token);
        reader.readKeys(template);
        var provider = new ProtectedCacheValueProvider(remote);

        provider.prefetchAsync(reader).join();

        var destination = new char[256];
        var written = new ConfigurationItemResolver(token, reader, provider).resolve(template, destination);

        assertEquals("User=app;Password=s3cret;Again=app", new String(destination, 0, written));
        assertEquals(Set.of("app-config#user", "app-config#password"), remote.asyncFetches);
        assertEquals(Set.of(), remote.blockingFetches);
    }

    @Test
    void prefetchAsync_SkipsKeysTheCacheDoesNotHave() {
        var remote = new RemoteSource();
        remote.with("present", "value");
        var provider = new ProtectedCacheValueProvider(remote);

        provider.prefetchAsync(List.of("present", "absent", "absent")).join();

        assertEquals(1, remote.lengthLookupCount("present"));
        assertEquals(1, remote.lengthLookupCount("absent"));
        assertEquals(ValueStatus.NOT_FOUND, provider.tryGetChars("absent", CharBuffer.allocate(16)));
        assertEquals(ValueStatus.NOT_FOUND, provider.tryGetBytes("absent", ByteBuffer.allocate(16)));
    }

    @Test
    void prefetchAsync_ReportsAFailingLookupThroughItsFuture() {
        var provider = new ProtectedCacheValueProvider(new FailingAsyncCache());

        var error = assertThrows(CompletionException.class, () -> provider.prefetchAsync(List.of("item")).join());

        assertInstanceOf(IllegalStateException.class, error.getCause());
    }

    @Test
    void members_RejectNullArguments() {
        var secrets = cache();
        var provider = new ProtectedCacheValueProvider(secrets);

        assertSame(secrets, provider.cache());
        assertThrows(NullPointerException.class, () -> new ProtectedCacheValueProvider(null));
        assertThrows(NullPointerException.class, () -> provider.tryGetBytes(null, ByteBuffer.allocate(1)));
        assertThrows(NullPointerException.class, () -> provider.tryGetChars(null, CharBuffer.allocate(1)));
        assertThrows(NullPointerException.class, () -> provider.prefetchAsync((ConfigurationItemReader) null));
        assertThrows(NullPointerException.class, () -> provider.prefetchAsync((Iterable<String>) null));
        assertThrows(NullPointerException.class, () -> ConfigurationResolverBuilderExtensions.addProtectedCache(null, secrets));
        assertThrows(NullPointerException.class, () -> ConfigurationResolverBuilderExtensions.addProtectedCache(new ConfigurationResolverBuilderImpl(), null));
    }

    /** A cache whose asynchronous lookup fails, as a remote store that refuses access does. */
    private static final class FailingAsyncCache implements ProtectedReadOnlyCache {
        @Override
        public int decrypt(String name, byte[] result) {
            return 0;
        }

        @Override
        public int decrypt(String name, char[] result) {
            return 0;
        }

        @Override
        public java.util.OptionalInt findMaxDecryptedLength(String name) {
            throw new IllegalStateException("access denied");
        }
    }
}
