package io.github.runsecure.hkdfguard.cache;

import static io.github.runsecure.hkdfguard.cache.RemoteSecretCacheTest.decryptString;
import static io.github.runsecure.hkdfguard.cache.TestRings.utf8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Names holding a key ("secret#key"): one fetch caching a secret's keys, and SecretValueSink's key setters. */
class SecretKeysTest {
    // A key/value secret as AWS Secrets Manager's console stores one.
    private static final String KEY_VALUE_SECRET = """
            {
              "test-credential-1": "This is my first credential",
              "service-credential-3": "This is my third credential",
              "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
              "domain-credential-17": "fakedomain/thiscredential"
            }""";

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

    private static String decryptLong(RemoteSecretCache cache, String name) {
        var result = new char[512];
        return new String(result, 0, cache.decrypt(name, result));
    }

    private static void setJson(SecretValueSink sink, String json) {
        sink.setBytesWithJsonKeys(utf8(json));
    }

    @Test
    void oneFetch_CachesTheWholeValueAndEveryKey() {
        var cache = create();
        cache.onFetch = (name, sink) -> setJson(sink, KEY_VALUE_SECRET);

        assertEquals("0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==", decryptLong(cache, "creds#api-credential-21"));
        assertEquals("This is my first credential", decryptLong(cache, "creds#test-credential-1"));
        assertEquals("This is my third credential", decryptLong(cache, "creds#service-credential-3"));
        assertEquals("fakedomain/thiscredential", decryptLong(cache, "creds#domain-credential-17"));
        assertEquals(KEY_VALUE_SECRET, decryptLong(cache, "creds"));

        assertEquals(List.of("creds"), List.copyOf(cache.fetches));
    }

    @Test
    void concurrentMissesOnDifferentKeys_ShareOneFetch() throws Exception {
        var cache = create();
        var release = new CountDownLatch(1);
        cache.onFetch = (name, sink) -> {
            RemoteSecretCacheTest.await(release);
            setJson(sink, "{\"a\":\"1\",\"b\":\"2\",\"c\":\"3\"}");
        };

        var names = List.of("s#a", "s#b", "s#c", "s");
        var lookups = names.stream().map(name -> CompletableFuture.supplyAsync(() -> decryptString(cache, name))).toList();
        Futures.sleep(200);
        release.countDown();

        var expected = List.of("1", "2", "3", "{\"a\":\"1\",\"b\":\"2\",\"c\":\"3\"}");
        for (var i = 0; i < names.size(); i++)
            assertEquals(expected.get(i), lookups.get(i).get(10, TimeUnit.SECONDS));
        assertEquals(1, cache.fetches.size());
    }

    @Test
    void aKeyTheSecretDoesntHold_IsMissing_AndFetchesAgain_WithoutReplacingWhatIsCached() {
        var cache = create();
        cache.onFetch = (name, sink) -> setJson(sink, "{\"a\":\"first\"}");
        assertEquals("first", decryptString(cache, "s#a"));

        assertEquals(0, cache.decrypt("s#b", new byte[16]));

        cache.onFetch = (name, sink) -> setJson(sink, "{\"a\":\"second\",\"b\":\"added\"}");
        assertEquals("added", decryptString(cache, "s#b"));
        assertEquals("first", decryptString(cache, "s#a"));
        assertEquals(3, cache.fetches.size());
    }

    @Test
    void keysAreMatchedExactly_EvenWhereSecretNamesIgnoreCase() {
        var cache = create(SecretNameMatching.IGNORE_ASCII_CASE);
        cache.onFetch = (name, sink) -> setJson(sink, "{\"Key\":\"upper\",\"key\":\"lower\"}");

        assertEquals("upper", decryptString(cache, "Db#Key"));
        assertEquals("lower", decryptString(cache, "DB#key"));
        assertEquals("upper", decryptString(cache, "db#Key"));
        assertEquals(0, cache.decrypt("db#KEY", new byte[16]));

        assertEquals(List.of("Db", "db"), List.copyOf(cache.fetches));
    }

    @Test
    void underExactMatching_SecretNamesAndKeysAreBothExact() {
        var cache = create();
        cache.onFetch = (name, sink) -> setJson(sink, "{\"Pass\":\"" + name + "\"}");

        assertEquals("Prod/Db", decryptString(cache, "Prod/Db#Pass"));
        assertEquals("prod/db", decryptString(cache, "prod/db#Pass"));
        assertEquals(0, cache.decrypt("prod/db#pass", new byte[16]));
    }

    @ParameterizedTest
    @ValueSource(strings = {"s#", "s#a#b", "s#a b", "s#bang!", "s#café", "#key", "in:valid#key"})
    void aNameWhoseSecretOrKeyIsntOne_IsMissing_WithoutAFetch(String name) {
        var cache = create();

        assertEquals(0, cache.decrypt(name, new byte[16]));
        assertFalse(cache.findMaxDecryptedLength(name).isPresent());
        assertTrue(cache.fetches.isEmpty());
    }

    @Test
    void isValidKey_AcceptsPrintableAsciiButSpaceBangAndHash_UpToTheLimit() {
        assertTrue(RemoteSecretCache.isValidKey("a"));
        assertTrue(RemoteSecretCache.isValidKey("ConnectionStrings:Admin"));
        assertTrue(RemoteSecretCache.isValidKey("\"$%&'()*+,-./0-9;<=>?@A-Z[\\]^_`a-z{|}~"));
        assertTrue(RemoteSecretCache.isValidKey("k".repeat(RemoteSecretCache.MAX_KEY_LENGTH)));
        assertFalse(RemoteSecretCache.isValidKey("k".repeat(RemoteSecretCache.MAX_KEY_LENGTH + 1)));
        assertFalse(RemoteSecretCache.isValidKey(null));
        assertFalse(RemoteSecretCache.isValidKey(""));
        assertFalse(RemoteSecretCache.isValidKey("a b"));
        assertFalse(RemoteSecretCache.isValidKey("a!"));
        assertFalse(RemoteSecretCache.isValidKey("a#"));
        assertFalse(RemoteSecretCache.isValidKey("tab\t"));
        assertFalse(RemoteSecretCache.isValidKey("del\u007f"));
    }

    @Test
    void withADefaultKey_ANameWithoutOne_ReadsThatKey_NotTheWholeValue() {
        var cache = create();
        cache.defaultKeyToRead = "value";
        cache.onFetch = (name, sink) -> {
            sink.setText("the whole value");
            sink.setKeyBytes("value", utf8("the default key"));
            sink.setKeyBytes("other", utf8("another key"));
        };

        assertEquals("the default key", decryptString(cache, "s"));
        assertEquals("the default key", decryptString(cache, "s#value"));
        assertEquals("another key", decryptString(cache, "s#other"));
        assertEquals(1, cache.fetches.size());
    }

    @Test
    void setKeyBytes_ZeroesWhatItsGiven_AndRefusesAnInvalidKey() {
        var cache = create();
        var given = new byte[] {1, 2, 3};
        var refused = new byte[] {4, 5, 6};
        cache.onFetch = (name, sink) -> {
            assertThrows(IllegalArgumentException.class, () -> sink.setKeyBytes("not a key", refused));
            assertThrows(IllegalArgumentException.class, () -> sink.setKeyBytes(null, refused));
            sink.setKeyBytes("k", given);
        };

        var result = new byte[16];
        assertArrayEquals(new byte[] {1, 2, 3}, Arrays.copyOf(result, cache.decrypt("s#k", result)));
        assertArrayEquals(new byte[3], given);
        assertArrayEquals(new byte[3], refused);
    }

    @Test
    void settingAKeyTwice_Throws_AndNothingIsCached() {
        var cache = create();
        cache.onFetch = (name, sink) -> {
            sink.setKeyBytes("k", utf8("first"));
            sink.setText("whole");
            sink.setKeyBytes("k", utf8("second"));
        };

        assertThrows(IllegalStateException.class, () -> cache.decrypt("s#k", new byte[16]));

        cache.onFetch = null;
        assertEquals(0, cache.decrypt("s", new byte[16]));
        assertEquals(0, cache.decrypt("s#k", new byte[16]));
    }

    @Test
    void anEmptyKey_IsMissing_AndCanStillBeSetAfterwards() {
        var cache = create();
        cache.onFetch = (name, sink) -> {
            sink.setKeyBytes("k", new byte[0]);
            sink.setKeyBytes("k", utf8("set"));
        };

        assertEquals("set", decryptString(cache, "s#k"));
    }

    @Test
    void aSinkKeptPastItsFetch_RefusesKeys() {
        var cache = create();
        var kept = new SecretValueSink[1];
        cache.onFetch = (name, sink) -> kept[0] = sink;
        assertEquals(0, cache.decrypt("s#k", new byte[16]));

        var bytes = new byte[] {9};
        assertThrows(IllegalStateException.class, () -> kept[0].setKeyBytes("k", bytes));
        assertEquals(0, bytes[0]);
        var json = utf8("{\"k\":\"v\"}");
        assertThrows(IllegalStateException.class, () -> kept[0].setBytesWithJsonKeys(json));
        assertArrayEquals(new byte[json.length], json);
    }

    @Test
    void jsonMembers_AreCachedAsTheirText_OrLeftOut() {
        var cache = create();
        cache.onFetch = (name, sink) -> setJson(sink, """
                {"text":"a\\"b\\\\cé\\n","int":3306,"real":-1.5e3,"yes":true,"no":false,
                 "null":null,"object":{"x":"y"},"array":["z"],"empty":"","bad key":"x","bang!":"x","Ascaped":"name"}
                """);

        assertEquals("a\"b\\cé\n", decryptString(cache, "s#text"));
        assertEquals("3306", decryptString(cache, "s#int"));
        assertEquals("-1.5e3", decryptString(cache, "s#real"));
        assertEquals("true", decryptString(cache, "s#yes"));
        assertEquals("false", decryptString(cache, "s#no"));
        assertEquals("name", decryptString(cache, "s#Ascaped"));
        for (var key : List.of("null", "object", "array", "empty", "x"))
            assertEquals(0, cache.decrypt("s#" + key, new byte[16]));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "plain text",
            "[\"a\",\"b\"]",
            "\"a json string\"",
            "42",
            "{\"k\":\"unterminated",
            "{\"k\":\"v\"} trailing",
            "{\"k\":\"v\"}{\"k\":\"w\"}",
            "{\"k\":\"v\", // a comment\n\"j\":\"w\"}",
            "{\"k\":\"\\ud800\"}",
    })
    void aValueThatIsntOneJsonObject_IsCachedWholeOnly(String value) {
        var cache = create();
        cache.onFetch = (name, sink) -> setJson(sink, value);

        assertEquals(value, decryptString(cache, "s"));
        assertEquals(0, cache.decrypt("s#k", new byte[16]));
        assertEquals(0, cache.decrypt("s#a", new byte[16]));
    }

    @Test
    void aJsonObjectWithWhitespaceAround_IsSplit() {
        var cache = create();
        cache.onFetch = (name, sink) -> setJson(sink, "  \r\n{\"k\":\"v\"}\n  ");

        assertEquals("v", decryptString(cache, "s#k"));
    }

    @Test
    void aDuplicatedKey_IsRefused_AndNothingIsCached() {
        var cache = create();
        cache.onFetch = (name, sink) -> setJson(sink, "{\"dup-key-name\":\"a\",\"other\":\"b\",\"dup-key-name\":\"c\"}");

        // The key is part of a name, which is logged only with sensitive logging on; an error log carries the message.
        var e = assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("s#other", new byte[16]));
        assertFalse(e.getMessage().contains("dup-key-name"));

        cache.onFetch = null;
        assertEquals(0, cache.decrypt("s", new byte[16]));
    }

    @Test
    void setBytesWithJsonKeys_ZeroesWhatItsGiven() {
        var cache = create();
        var given = utf8("{\"k\":\"v\"}");
        cache.onFetch = (name, sink) -> sink.setBytesWithJsonKeys(given);

        assertEquals("v", decryptString(cache, "s#k"));
        assertArrayEquals(new byte[given.length], given);
    }

    @Test
    void anEmptyValue_WithJsonKeys_IsMissing() {
        var cache = create();
        cache.onFetch = (name, sink) -> sink.setBytesWithJsonKeys(new byte[0]);

        assertEquals(0, cache.decrypt("s", new byte[16]));
    }
}
