package io.github.runsecure.hkdfguard.abstractions;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class ProtectedCacheBaseTest {
    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void decryptBytes_ForAStoredName_RevealsTheValue() {
        var cache = new TestCache();
        cache.store("item", utf8("value"));

        var result = new byte[16];
        var written = cache.decrypt("item", result);

        assertArrayEquals(utf8("value"), Arrays.copyOf(result, written));
    }

    @Test
    void decryptChars_ForAStoredName_RevealsTheValue() {
        var cache = new TestCache();
        cache.storeChars("item", "héllo".toCharArray());

        var result = new char[16];
        var written = cache.decrypt("item", result);

        assertEquals("héllo", new String(result, 0, written));
    }

    @Test
    void decrypt_ForAMissingName_ReturnsZeroForBothOverloads() {
        var cache = new TestCache();

        assertEquals(0, cache.decrypt("missing", new byte[16]));
        assertEquals(0, cache.decrypt("missing", new char[16]));
    }

    @Test
    void names_AreCaseInsensitive() {
        var cache = new TestCache();
        cache.store("Item", utf8("value"));

        assertEquals(5, cache.decrypt("ITEM", new byte[16]));
    }

    @Test
    void findMaxDecryptedLength_ForAStoredName_ReturnsTheEncryptedLength() {
        var cache = new TestCache();
        cache.store("item", utf8("value"));

        assertEquals(5, cache.findMaxDecryptedLength("item").orElseThrow());
    }

    @Test
    void findMaxDecryptedLength_ForAMissingName_IsEmpty() {
        assertTrue(new TestCache().findMaxDecryptedLength("missing").isEmpty());
    }

    @Test
    void decrypt_OnAMiss_PopulatesThroughTryPopulate() {
        var cache = new TestCache();
        cache.onTryPopulate = name -> {
            cache.store(name, utf8("fetched"));
            return true;
        };

        var result = new byte[16];
        var written = cache.decrypt("remote", result);

        assertArrayEquals(utf8("fetched"), Arrays.copyOf(result, written));
        assertEquals(List.of("remote"), cache.populateRequests);
    }

    @Test
    void decrypt_WhenTryPopulateClaimsSuccessButStoresNothing_ReturnsZero() {
        var cache = new TestCache();
        cache.onTryPopulate = name -> true;

        assertEquals(0, cache.decrypt("remote", new byte[16]));
        assertTrue(cache.findMaxDecryptedLength("remote").isEmpty());
    }

    @Test
    void decrypt_OnAHit_DoesNotCallTryPopulate() {
        var cache = new TestCache();
        cache.store("item", utf8("value"));

        cache.decrypt("item", new byte[16]);

        assertTrue(cache.populateRequests.isEmpty());
    }

    @Test
    void encryptChars_ZeroesTheCallersChars() {
        var cache = new TestCache();
        var plaintext = "secret".toCharArray();

        cache.storeChars("item", plaintext);

        assertArrayEquals(new char[6], plaintext);
    }

    @Test
    void decrypt_WhenTheKeyFails_RethrowsForBothOverloads() {
        var key = new MaskingKey();
        key.throwOnDecrypt = true;
        var cache = new TestCache(key);
        cache.store("item", utf8("value"));

        assertThrows(IllegalStateException.class, () -> cache.decrypt("item", new byte[16]));
        assertThrows(IllegalStateException.class, () -> cache.decrypt("item", new char[16]));
    }

    @Test
    void decrypt_WithSensitiveLoggingEnabled_StillWorksForBothOverloads() {
        var original = HkdfGuardTelemetry.ROOT.isSensitiveLoggingEnabled();
        HkdfGuardTelemetry.ROOT.setSensitiveLoggingEnabled(true);
        try {
            var cache = new TestCache();
            cache.store("item", utf8("value"));

            assertEquals(5, cache.decrypt("item", new byte[16]));
            assertEquals(5, cache.decrypt("item", new char[16]));
        } finally {
            HkdfGuardTelemetry.ROOT.setSensitiveLoggingEnabled(original);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {512, 513, 2 * 1024 * 1024})
    void decryptChars_WithSmallAndLargeValues_RoundTrips(int length) {
        var cache = new TestCache();
        var value = "x".repeat(length);
        cache.storeChars("big", value.toCharArray());

        var result = new char[length];
        var written = cache.decrypt("big", result);

        assertEquals(length, written);
        assertEquals(value, new String(result));
    }

    @Test
    void store_WithAnEmptyValue_IsRejectedForBothOverloads() {
        var cache = new TestCache();

        assertThrows(IllegalArgumentException.class, () -> cache.store("empty", new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> cache.storeChars("empty", new char[0]));
        assertTrue(cache.findMaxDecryptedLength("empty").isEmpty());
    }

    @Test
    void everyValue_IsEncryptedAndDecryptedWithItsNamesAad() {
        var key = new MaskingKey();
        var cache = new TestCache(key);

        cache.store("Item", utf8("value"));
        cache.decrypt("ITEM", new byte[16]);
        cache.decrypt("item", new char[16]);

        var expected = ProtectedCacheBase.aadFor("Item");
        assertEquals(1, key.encryptAads.size());
        assertArrayEquals(expected, key.encryptAads.getFirst());
        assertEquals(2, key.decryptAads.size());
        key.decryptAads.forEach(aad -> assertArrayEquals(expected, aad));
    }

    @Test
    void aadFor_IsThePrefixPlusTheNameWithOnlyAsciiLettersUpperCased() {
        // A known vector, for every port to reproduce byte for byte.
        assertArrayEquals(utf8("HkdfGuard.Cache:API-KEY_1:CAFé"), ProtectedCacheBase.aadFor("api-Key_1:café"));
        assertArrayEquals(ProtectedCacheBase.aadFor("item"), ProtectedCacheBase.aadFor("ITEM"));
        assertFalse(Arrays.equals(ProtectedCacheBase.aadFor("café"), ProtectedCacheBase.aadFor("CAFÉ")));
    }

    @Test
    void aadFor_RejectsANullName_AndInvalidUtf16() {
        assertThrows(NullPointerException.class, () -> ProtectedCacheBase.aadFor(null));
        assertThrows(IllegalArgumentException.class, () -> ProtectedCacheBase.aadFor("bad\uD800name"));
    }

    @Test
    void store_UnderAnInvalidUtf16Name_Throws_AndStillZeroesThePlaintext() {
        var cache = new TestCache();
        var plaintext = utf8("value");

        assertThrows(IllegalArgumentException.class, () -> cache.store("bad\uD800name", plaintext));

        assertArrayEquals(new byte[5], plaintext);
        assertTrue(cache.findMaxDecryptedLength("bad\uD800name").isEmpty());
    }

    @Test
    void aValueStoredUnderADifferentNameThanItWasEncryptedFor_IsDecryptedWithTheLookupNamesAad() {
        // The masking key can't fail authentication, so check what a real AEAD would be asked:
        // the AAD of the name looked up, not the one encrypted for - which is what makes it fail.
        var key = new MaskingKey();
        var cache = new TestCache(key);

        cache.storeUnderAnotherName("admin", "reporting", utf8("secret"));
        cache.decrypt("reporting", new byte[16]);

        assertArrayEquals(ProtectedCacheBase.aadFor("admin"), key.encryptAads.getFirst());
        assertArrayEquals(ProtectedCacheBase.aadFor("reporting"), key.decryptAads.getFirst());
    }

    @Test
    void longNames_StillRoundTripThroughBothOverloads() {
        var name = "n".repeat(600);
        var cache = new TestCache();

        cache.store(name, utf8("value"));

        assertEquals(5, cache.decrypt(name.toUpperCase(), new byte[16]));
        var chars = new char[16];
        assertEquals("value", new String(chars, 0, cache.decrypt(name, chars)));
    }

    @Test
    void nonAsciiCaseVariants_AreDifferentNames() {
        var cache = new TestCache();
        cache.store("café", utf8("value"));

        assertEquals(0, cache.decrypt("CAFÉ", new byte[16]));
        assertEquals(5, cache.decrypt("CAFé", new byte[16]));
    }

    @ParameterizedTest
    @CsvSource({
            "item,ITEM,true",
            "Item-1_x,iTEM-1_X,true",
            "café,CAFÉ,false",
            "ſecret,Secret,false",
            "item,items,false",
            "item,itex,false",
            "'','',true",
    })
    void canonicalName_IgnoresOnlyAsciiCase(String x, String y, boolean equal) {
        assertEquals(equal, TestCache.canonical(x).equals(TestCache.canonical(y)));
    }

    @Test
    void eachEntry_RecordsTheVersionItWasEncryptedUnder_AndDecryptsWithThatVersionsKey() {
        var first = new MaskingKey();
        var second = new MaskingKey();
        var ring = new FakeKeyRing(first, 1);
        var cache = new TestCache(ring);

        cache.store("before", utf8("one"));
        ring.add(2, second); // the ring rotates
        cache.store("after", utf8("two"));

        assertEquals(1, cache.versionOf("before"));
        assertEquals(2, cache.versionOf("after"));
        assertEquals(1, first.encryptAads.size());
        assertEquals(1, second.encryptAads.size());

        var result = new byte[8];
        assertArrayEquals(utf8("one"), Arrays.copyOf(result, cache.decrypt("before", result)));
        assertArrayEquals(utf8("two"), Arrays.copyOf(result, cache.decrypt("after", result)));
        assertEquals(1, first.decryptAads.size());
        assertEquals(1, second.decryptAads.size());
    }

    @Test
    void decrypt_WhenTheEntrysVersionIsNoLongerInTheRing_ThrowsNoSuchElement() {
        var ring = new FakeKeyRing(new MaskingKey(), 1);
        var cache = new TestCache(ring);
        cache.store("item", utf8("value"));
        ring.add(2, new MaskingKey());
        ring.remove(1);

        assertThrows(NoSuchElementException.class, () -> cache.decrypt("item", new byte[16]));
        assertThrows(NoSuchElementException.class, () -> cache.decrypt("item", new char[16]));
    }

    @Test
    void putEntryIfAbsent_StoresOnlyTheFirst_AndRemoveEntryDropsIt() {
        var cache = new TestCache();

        assertTrue(cache.storeIfAbsent("item", utf8("one")));
        assertFalse(cache.storeIfAbsent("ITEM", utf8("two")));
        var result = new byte[8];
        assertArrayEquals(utf8("one"), Arrays.copyOf(result, cache.decrypt("item", result)));

        assertTrue(cache.remove("Item"));
        assertEquals(0, cache.decrypt("item", result));
    }

    // The smallest concrete cache: exposes encrypt/encryptChars for storing, and records (and
    // optionally answers) tryPopulate calls - falling back to the base implementation otherwise.
    @Test
    void decryptAsync_ForAStoredName_RevealsTheValueForBothOverloads() {
        var cache = new TestCache();
        cache.storeChars("item", "h\u00e9llo".toCharArray());

        var bytes = new byte[16];
        assertArrayEquals(utf8("h\u00e9llo"), Arrays.copyOf(bytes, await(cache.decryptAsync("ITEM", bytes))));
        var chars = new char[16];
        assertEquals("h\u00e9llo", new String(chars, 0, await(cache.decryptAsync("item", chars))));
        assertEquals(OptionalInt.of(6), await(cache.findMaxDecryptedLengthAsync("item")));
        assertTrue(cache.populateRequests.isEmpty());
    }

    @Test
    void decryptAsync_ForAMissingName_ReturnsZero_AfterAskingTryPopulateByDefault() {
        var cache = new TestCache();

        assertEquals(0, await(cache.decryptAsync("missing", new byte[16])));
        assertEquals(0, await(cache.decryptAsync("missing", new char[16])));
        assertEquals(OptionalInt.empty(), await(cache.findMaxDecryptedLengthAsync("missing")));
        assertEquals(List.of("missing", "missing", "missing"), cache.populateRequests);
    }

    @Test
    void decryptAsync_OnAMiss_PopulatesThroughTryPopulateAsync_WhenOverridden() {
        var cache = new TestCache();
        cache.onTryPopulateAsync = name -> CompletableFuture.supplyAsync(() -> {
            cache.store(name, utf8("fetched"));
            return true;
        });

        var result = new byte[16];
        assertArrayEquals(utf8("fetched"), Arrays.copyOf(result, await(cache.decryptAsync("remote", result))));
        assertTrue(cache.populateRequests.isEmpty());
    }

    @Test
    void decryptAsync_WhenTryPopulateClaimsSuccessButStoresNothing_ReturnsZero() {
        var cache = new TestCache();
        cache.onTryPopulate = name -> true;

        assertEquals(0, await(cache.decryptAsync("remote", new byte[16])));
        assertEquals(OptionalInt.empty(), await(cache.findMaxDecryptedLengthAsync("remote")));
    }

    @Test
    void decryptAsync_WhenTryPopulateFails_FailsForEveryMember() {
        var cache = new TestCache();
        cache.onTryPopulate = name -> {
            throw new IllegalStateException("unreachable");
        };

        assertFailsWith(IllegalStateException.class, cache.decryptAsync("remote", new byte[16]));
        assertFailsWith(IllegalStateException.class, cache.decryptAsync("remote", new char[16]));
        assertFailsWith(IllegalStateException.class, cache.findMaxDecryptedLengthAsync("remote"));
    }

    @Test
    void decryptAsync_WhenTryPopulateAsyncThrowsOrReturnsNull_Fails() {
        var cache = new TestCache();
        cache.onTryPopulateAsync = name -> {
            throw new IllegalStateException("thrown");
        };
        assertFailsWith(IllegalStateException.class, cache.decryptAsync("remote", new byte[16]));

        cache.onTryPopulateAsync = name -> null;
        assertFailsWith(NullPointerException.class, cache.decryptAsync("remote", new byte[16]));
    }

    @Test
    void decryptAsync_WithANullName_Fails() {
        var cache = new TestCache();

        assertFailsWith(NullPointerException.class, cache.decryptAsync(null, new byte[16]));
        assertFailsWith(NullPointerException.class, cache.findMaxDecryptedLengthAsync(null));
    }

    @Test
    void cancellingALookup_CancelsItsPopulation() {
        var cache = new TestCache();
        var population = new CompletableFuture<Boolean>();
        cache.onTryPopulateAsync = name -> population;

        var decrypted = cache.decryptAsync("remote", new byte[16]);
        var length = cache.findMaxDecryptedLengthAsync("remote");
        assertTrue(decrypted.cancel(true));

        assertTrue(population.isCancelled());
        assertTrue(length.isCompletedExceptionally());
    }

    @Test
    void decryptAsync_WhenTheKeyFails_FailsForBothOverloads() {
        var key = new MaskingKey();
        var cache = new TestCache(key);
        cache.store("item", utf8("value"));
        key.throwOnDecrypt = true;

        assertFailsWith(IllegalStateException.class, cache.decryptAsync("item", new byte[16]));
        assertFailsWith(IllegalStateException.class, cache.decryptAsync("item", new char[16]));
    }

    @Test
    void decryptAsync_WithSensitiveLoggingEnabled_StillWorks() {
        var original = HkdfGuardTelemetry.ROOT.isSensitiveLoggingEnabled();
        HkdfGuardTelemetry.ROOT.setSensitiveLoggingEnabled(true);
        try {
            var cache = new TestCache();
            cache.store("item", utf8("value"));

            assertEquals(5, await(cache.decryptAsync("item", new byte[16])));
        } finally {
            HkdfGuardTelemetry.ROOT.setSensitiveLoggingEnabled(original);
        }
    }

    @Test
    void theInterfacesDefaultAsyncMembers_CallTheSynchronousOnes() {
        ProtectedReadOnlyCache cache = new SyncOnlyCache();

        var bytes = new byte[16];
        assertArrayEquals(utf8("bytes"), Arrays.copyOf(bytes, await(cache.decryptAsync("item", bytes))));
        var chars = new char[16];
        assertEquals("chars", new String(chars, 0, await(cache.decryptAsync("item", chars))));
        assertEquals(OptionalInt.of(42), await(cache.findMaxDecryptedLengthAsync("item")));
        assertEquals(OptionalInt.empty(), await(cache.findMaxDecryptedLengthAsync("missing")));
    }

    @Test
    void theInterfacesDefaultAsyncMembers_ReportAFailureThroughTheFuture() {
        ProtectedReadOnlyCache cache = new SyncOnlyCache();

        assertFailsWith(NullPointerException.class, cache.decryptAsync(null, new byte[16]));
        assertFailsWith(NullPointerException.class, cache.decryptAsync(null, new char[16]));
        assertFailsWith(NullPointerException.class, cache.findMaxDecryptedLengthAsync(null));
    }

    private static <T> T await(CompletableFuture<T> future) {
        try {
            return future.get(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static void assertFailsWith(Class<? extends Throwable> type, CompletableFuture<?> future) {
        var e = assertThrows(ExecutionException.class, () -> future.get(10, TimeUnit.SECONDS));
        assertInstanceOf(type, e.getCause());
    }

    // A ProtectedReadOnlyCache with only the synchronous members, as one written before the
    // asynchronous ones existed. Each throws NullPointerException for a null name.
    private static final class SyncOnlyCache implements ProtectedReadOnlyCache {
        @Override
        public int decrypt(String name, byte[] result) {
            name.length();
            var bytes = utf8("bytes");
            System.arraycopy(bytes, 0, result, 0, bytes.length);
            return bytes.length;
        }

        @Override
        public int decrypt(String name, char[] result) {
            name.length();
            "chars".getChars(0, 5, result, 0);
            return 5;
        }

        @Override
        public OptionalInt findMaxDecryptedLength(String name) {
            return name.equals("item") ? OptionalInt.of(42) : OptionalInt.empty();
        }
    }

    private static final class TestCache extends ProtectedCacheBase {
        Predicate<String> onTryPopulate;
        Function<String, CompletableFuture<Boolean>> onTryPopulateAsync;
        final List<String> populateRequests = new ArrayList<>();

        TestCache() {
            this(new MaskingKey());
        }

        TestCache(DataEncryptionKey key) {
            this(new FakeKeyRing(key));
        }

        TestCache(KeyRing ring) {
            super(ring);
        }

        void store(String name, byte[] plaintext) {
            putEntry(name, encrypt(name, plaintext));
        }

        boolean storeIfAbsent(String name, byte[] plaintext) {
            return putEntryIfAbsent(name, encrypt(name, plaintext));
        }

        void storeChars(String name, char[] plaintext) {
            putEntry(name, encryptChars(name, plaintext));
        }

        void storeUnderAnotherName(String encryptedFor, String storedAs, byte[] plaintext) {
            putEntry(storedAs, encrypt(encryptedFor, plaintext));
        }

        boolean remove(String name) {
            return removeEntry(name);
        }

        int versionOf(String name) {
            return getEntry(name).keyVersion();
        }

        static String canonical(String name) {
            return canonicalName(name);
        }

        @Override
        protected boolean tryPopulate(String name) {
            populateRequests.add(name);
            return onTryPopulate != null ? onTryPopulate.test(name) : super.tryPopulate(name);
        }

        @Override
        protected CompletableFuture<Boolean> tryPopulateAsync(String name) {
            return onTryPopulateAsync != null ? onTryPopulateAsync.apply(name) : super.tryPopulateAsync(name);
        }
    }

    // A reversible stand-in for real AEAD: XORs every byte with a fixed mask, same length out as in.
    private static final class MaskingKey implements DataEncryptionKey {
        private static final byte MASK = (byte) 0xA5;

        boolean throwOnDecrypt;
        final List<byte[]> encryptAads = new ArrayList<>();
        final List<byte[]> decryptAads = new ArrayList<>();

        @Override
        public byte[] encrypt(byte[] plaintext) {
            return encrypt(plaintext, new byte[0]);
        }

        @Override
        public byte[] encrypt(byte[] plaintext, byte[] aad) {
            encryptAads.add(aad.clone());
            var output = new byte[plaintext.length];
            for (var i = 0; i < plaintext.length; i++)
                output[i] = (byte) (plaintext[i] ^ MASK);
            return output;
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] result) {
            return decrypt(ciphertext, new byte[0], result);
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
            decryptAads.add(aad.clone());
            if (throwOnDecrypt)
                throw new IllegalStateException("decrypt failed");

            for (var i = 0; i < ciphertext.length; i++)
                result[i] = (byte) (ciphertext[i] ^ MASK);
            return ciphertext.length;
        }
    }
}
