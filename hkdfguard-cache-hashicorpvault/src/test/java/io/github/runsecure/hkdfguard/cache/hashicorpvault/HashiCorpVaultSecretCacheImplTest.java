package io.github.runsecure.hkdfguard.cache.hashicorpvault;

import static io.github.runsecure.hkdfguard.cache.hashicorpvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheCollectionImpl;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheImpl;
import io.github.runsecure.hkdfguard.cache.hashicorpvault.FakeVault.Answer;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.event.Level;

/** The cache's real HttpClient against a fake Vault on loopback. */
class HashiCorpVaultSecretCacheImplTest {
    private static final String TOKEN_PURPOSE = HashiCorpVaultSecretCacheImpl.TOKEN_PURPOSE;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final FakeVault vault = track(new FakeVault());

    @AfterEach
    void closeEverything() throws Exception {
        Collections.reverse(closeables);
        for (var closeable : closeables)
            closeable.close();
    }

    private <T extends AutoCloseable> T track(T closeable) {
        closeables.add(closeable);
        return closeable;
    }

    private KeyRingImpl ring() {
        return track(TestRings.ring());
    }

    private HashiCorpVaultSecretCacheImpl create() {
        return create(options -> {
        });
    }

    private HashiCorpVaultSecretCacheImpl create(Consumer<HashiCorpVaultSecretCacheOptions.Builder> options) {
        return create(options, null);
    }

    private HashiCorpVaultSecretCacheImpl create(Consumer<HashiCorpVaultSecretCacheOptions.Builder> options, VaultTokenProvider tokens) {
        return create(vault, vault.address(), options, tokens, null);
    }

    // A cache on a ring of its own, with the cache's own HttpClient unless options supply one. No
    // backoff, only each retry's 0-100 ms of jitter, so a test that meets a 5xx stays quick.
    private HashiCorpVaultSecretCacheImpl create(FakeVault vault, URI address, Consumer<HashiCorpVaultSecretCacheOptions.Builder> options,
            VaultTokenProvider tokens, Logger logger) {
        var builder = HashiCorpVaultSecretCacheOptions.builder().retryDelay(Duration.ZERO);
        options.accept(builder);
        var ring = ring();
        var protector = ring.createProtector(TOKEN_PURPOSE);
        if (tokens instanceof FakeTokenProvider fake && fake.protector == null)
            fake.protector = protector;

        return track(new HashiCorpVaultSecretCacheImpl(address, tokens != null ? tokens : StaticVaultToken.protect(protector, FakeVault.TOKEN),
                protector, ring, builder.build(), logger));
    }

    // A cache on ring, given the fake's token protected for it.
    private HashiCorpVaultSecretCacheImpl newCache(URI address, KeyRingImpl ring, HashiCorpVaultSecretCacheOptions options) {
        var protector = ring.createProtector(TOKEN_PURPOSE);
        return track(new HashiCorpVaultSecretCacheImpl(address, StaticVaultToken.protect(protector, FakeVault.TOKEN), protector, ring, options, null));
    }

    private HashiCorpVaultSecretCacheImpl newCache(HashiCorpVaultSecretCacheOptions.Builder options) {
        return newCache(vault.address(), ring(), options.build());
    }

    private static HashiCorpVaultSecretCacheOptions.Builder options() {
        return HashiCorpVaultSecretCacheOptions.builder();
    }

    private static String decryptString(ProtectedReadOnlyCache cache, String name) {
        var result = new char[64];
        return new String(result, 0, cache.decrypt(name, result));
    }

    private static Thread.Builder.OfVirtual lookups() {
        return Thread.ofVirtual().name("lookup");
    }

    @Test
    void decrypt_OnMiss_ReadsTheOneSecret_ThenServesItFromTheCache() {
        var cache = create();
        vault.set("myapp/Db", "s3cret");

        assertEquals("s3cret", decryptString(cache, "myapp/Db"));
        var bytes = new byte[64];
        assertEquals("s3cret", new String(bytes, 0, cache.decrypt("myapp/Db", bytes), StandardCharsets.UTF_8));

        assertEquals(List.of("myapp/Db"), vault.reads());
        assertEquals(List.of("true"), vault.vaultRequestHeaders());
        assertEquals(List.of(), vault.unexpectedRequests());
    }

    @Test
    void oneRead_CachesEveryKeyTheSecretHolds() {
        var cache = create();
        vault.setData("myapp/db", Map.of("username", "app", "password", "s3cret", "value", "default", "Mixed-Case.key:1", "mixed"));

        assertEquals("s3cret", decryptString(cache, "myapp/db#password"));
        assertEquals("app", decryptString(cache, "myapp/db#username"));
        assertEquals("default", decryptString(cache, "myapp/db"));
        assertEquals("default", decryptString(cache, "myapp/db#value"));
        assertEquals("mixed", decryptString(cache, "myapp/db#Mixed-Case.key:1"));

        assertEquals(List.of("myapp/db"), vault.reads());
    }

    @Test
    void concurrentMissesOnDifferentKeys_ShareOneRead() throws Exception {
        var cache = create();
        vault.setData("shared", Map.of("a", "1", "b", "2", "value", "3"));
        var release = new CountDownLatch(1);
        vault.onRead = exchange -> awaitQuietly(release);

        var names = List.of("shared#a", "shared#b", "shared");
        var results = names.stream().map(name -> new CompletableFuture<String>()).toList();
        for (var i = 0; i < names.size(); i++) {
            var name = names.get(i);
            var result = results.get(i);
            lookups().start(() -> result.complete(decryptString(cache, name)));
        }
        Thread.sleep(200);
        release.countDown();

        assertEquals(List.of("1", "2", "3"), results.stream().map(Futures::await).toList());
        assertEquals(1, vault.reads().size());
    }

    @Test
    void concurrentMissesOnOneName_ShareOneFetch() throws Exception {
        var cache = create();
        vault.set("shared", "value");
        var release = new CountDownLatch(1);
        vault.onRead = exchange -> awaitQuietly(release);

        var results = IntStream.range(0, 8).mapToObj(i -> {
            var result = new CompletableFuture<String>();
            lookups().start(() -> result.complete(decryptString(cache, "shared")));
            return result;
        }).toList();
        Thread.sleep(200);
        release.countDown();

        results.forEach(result -> assertEquals("value", await(result)));
        assertEquals(1, vault.reads().size());
    }

    @Test
    void decryptAsync_ReadsWithoutBlocking() {
        var cache = create();
        vault.setData("myapp/db", Map.of("password", "s3cret", "value", "default"));

        var chars = new char[64];
        assertEquals("s3cret", new String(chars, 0, await(cache.decryptAsync("myapp/db#password", chars))));
        assertEquals("default", new String(chars, 0, await(cache.decryptAsync("myapp/db", chars))));
        assertEquals(0, await(cache.decryptAsync("missing", new byte[16])));
        assertTrue(await(cache.findMaxDecryptedLengthAsync("missing")).isEmpty());

        assertEquals(List.of("myapp/db", "missing", "missing"), vault.reads());
    }

    @Test
    void cancellingAnAsyncLookup_WhileTheProviderIsWaitedFor_CancelsTheProvidersFuture() throws Exception {
        var tokens = new FakeTokenProvider(true);
        tokens.next = call -> new CompletableFuture<>();
        var cache = create(options -> {
        }, tokens);

        var lookup = cache.decryptAsync("item", new byte[16]);
        Thread.sleep(100);
        lookup.cancel(true);

        assertTrue(lookup.isCancelled());
        assertTrue(eventually(() -> tokens.lastGiven != null && tokens.lastGiven.isCancelled()));
        assertEquals(List.of(), vault.reads());
    }

    @Test
    void cancellingAnAsyncLookup_WhileVaultIsAnswering_AbandonsTheRequest_AndIsNotRetried() throws Exception {
        var cache = create();
        var arrived = new CountDownLatch(1);
        vault.onRead = exchange -> {
            arrived.countDown();
            sleepQuietly(5_000);
        };

        var lookup = cache.decryptAsync("item", new byte[16]);
        assertTrue(arrived.await(10, TimeUnit.SECONDS));
        lookup.cancel(true);
        Thread.sleep(300);

        assertTrue(lookup.isCancelled());
        assertEquals(1, vault.reads().size());
    }

    @Test
    void interruptingASynchronousLookup_FailsItWithCancellation_AndKeepsTheInterruptStatus() throws Exception {
        var cache = create();
        var arrived = new CountDownLatch(1);
        vault.onRead = exchange -> {
            arrived.countDown();
            sleepQuietly(5_000);
        };

        var failure = new CompletableFuture<Throwable>();
        var stillInterrupted = new AtomicBoolean();
        var thread = Thread.ofPlatform().start(() -> {
            try {
                cache.decrypt("item", new byte[16]);
                failure.complete(null);
            } catch (Throwable e) {
                stillInterrupted.set(Thread.currentThread().isInterrupted());
                failure.complete(e);
            }
        });
        assertTrue(arrived.await(10, TimeUnit.SECONDS));
        thread.interrupt();

        assertInstanceOf(CancellationException.class, await(failure));
        assertTrue(stillInterrupted.get());
        assertEquals(1, vault.reads().size());
    }

    @Test
    void theDefaultKey_IsConfigurable() {
        var cache = create(options -> options.defaultKey("secret_value"));
        vault.setData("item", Map.of("value", "wrong", "secret_value", "right"));

        assertEquals("right", decryptString(cache, "item"));
    }

    @Test
    void kvVersion1_IsReadAtTheMountsOwnPath() {
        var v1 = track(new FakeVault("kv", VaultKvVersion.V1, ""));
        var cache = create(v1, v1.address(), options -> options.kvVersion(VaultKvVersion.V1).mountPath("kv"), null, null);
        v1.setData("myapp/db", Map.of("password", "v1 value"));

        assertEquals("v1 value", decryptString(cache, "myapp/db#password"));
        assertEquals(0, cache.decrypt("missing", new byte[16]));
        assertEquals(List.of(), v1.unexpectedRequests());
    }

    @Test
    void aNestedMountPath_AndAnAddressPrefix_AreKept() {
        var prefixed = track(new FakeVault("kv/team-a", VaultKvVersion.V2, "/vault"));
        var cache = create(prefixed, prefixed.address(), options -> options.mountPath("kv/team-a"), null, null);
        prefixed.set("item", "prefixed");

        assertEquals("prefixed", decryptString(cache, "item"));
        assertEquals(List.of(), prefixed.unexpectedRequests());
    }

    @Test
    void anAddressWithoutATrailingSlash_IsReadTheSame() {
        var prefixed = track(new FakeVault("secret", VaultKvVersion.V2, "/vault"));
        var address = prefixed.address().toString();
        var cache = create(prefixed, URI.create(address.substring(0, address.length() - 1)), options -> {
        }, null, null);
        prefixed.set("item", "prefixed");

        assertEquals("prefixed", decryptString(cache, "item"));
    }

    @Test
    void theNamespace_IsSent_OnlyWhenSet() {
        var withNamespace = create(options -> options.namespace("team-a/prod"));
        var without = create();
        vault.set("item", "value");

        decryptString(withNamespace, "item");
        decryptString(without, "item");

        assertEquals(List.of("team-a/prod", "(none)"), vault.namespaces());
    }

    @Test
    void everyFetch_AsksTheProviderForTheToken() {
        var tokens = new FakeTokenProvider();
        var cache = create(options -> {
        }, tokens);
        vault.set("a", "1");
        vault.set("b", "2");

        decryptString(cache, "a");
        decryptString(cache, "a");
        decryptString(cache, "b");

        assertEquals(2, tokens.calls());
        assertEquals(List.of(FakeVault.TOKEN, FakeVault.TOKEN), vault.tokens());
    }

    @Test
    void aRefusedToken_Propagates403_AndANewTokenIsUsedNextTime() {
        var tokens = new FakeTokenProvider();
        tokens.next = call -> CompletableFuture.completedFuture(call == 1 ? "hvs.expired" : FakeVault.TOKEN);
        var cache = create(options -> {
        }, tokens);
        vault.set("item", "value");

        var e = assertThrows(VaultRequestException.class, () -> cache.decrypt("item", new byte[16]));
        assertEquals(403, e.statusCode());
        assertTrue(e.getMessage().contains("permission denied"));
        assertFalse(e.getMessage().contains("hvs."));

        assertEquals("value", decryptString(cache, "item"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"has space", "tab\tinside", "café"})
    void aTokenThatCantBeSent_IsRefused_WithoutCallingVault(String token) {
        var cache = create(options -> {
        }, FakeTokenProvider.giving(token));

        assertThrows(IllegalStateException.class, () -> cache.decrypt("item", new byte[16]));
        assertEquals(List.of(), vault.reads());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", FakeVault.TOKEN, "enc::v1::not base64!", "enc::v1"})
    void anUnprotectedToken_IsRefused_WithoutCallingVault_OrQuotingIt(String handedOver) {
        var tokens = new FakeTokenProvider(true);
        tokens.next = call -> CompletableFuture.completedFuture(handedOver);
        var cache = create(options -> {
        }, tokens);

        var e = assertThrows(IllegalStateException.class, () -> cache.decrypt("item", new byte[16]));

        assertNull(e.getCause());
        if (!handedOver.isEmpty())
            assertFalse(e.getMessage().contains(handedOver));
        assertEquals(List.of(), vault.reads());
    }

    @Test
    void aNullProtectedToken_IsRefused_WithoutCallingVault() {
        var tokens = new FakeTokenProvider(true);
        tokens.next = call -> CompletableFuture.completedFuture(null);
        var cache = create(options -> {
        }, tokens);

        assertThrows(IllegalStateException.class, () -> cache.decrypt("item", new byte[16]));
        assertEquals(List.of(), vault.reads());
    }

    enum ForeignProtection { ANOTHER_PURPOSE, ANOTHER_RING, A_VERSION_NOT_ON_THE_RING }

    @ParameterizedTest
    @EnumSource(ForeignProtection.class)
    void aTokenProtectedWithAnotherKeyOrPurpose_IsRefused_WithoutCallingVault(ForeignProtection how) {
        var ring = ring();
        var protector = ring.createProtector(TOKEN_PURPOSE);
        DataProtector foreign = switch (how) {
            case ANOTHER_PURPOSE -> ring.createProtector("Some.Other.Purpose");
            case ANOTHER_RING -> ring().createProtector(TOKEN_PURPOSE);
            case A_VERSION_NOT_ON_THE_RING -> track(TestRings.ring(7)).createProtector(TOKEN_PURPOSE);
        };
        var cache = track(new HashiCorpVaultSecretCacheImpl(vault.address(), new StaticVaultToken(foreign.encrypt(FakeVault.TOKEN)), protector, ring,
                null, null));

        var e = assertThrows(IllegalStateException.class, () -> cache.decrypt("item", new byte[16]));

        assertNull(e.getCause());
        assertEquals(List.of(), vault.reads());
    }

    @Test
    void theTokenIsDecryptedForEachRequest_AndReachesVaultIntact() {
        var cache = create();
        vault.set("a", "1");
        vault.set("b", "2");

        assertEquals("1", decryptString(cache, "a"));
        assertEquals("2", decryptString(cache, "b"));

        assertEquals(List.of(FakeVault.TOKEN, FakeVault.TOKEN), vault.tokens());
    }

    @Test
    void aLongToken_IsSentWhole() {
        var longToken = "hvs." + "x".repeat(2_000);
        var cache = create(options -> {
        }, FakeTokenProvider.giving(longToken));

        // Not the fake's token, so Vault refuses it - after receiving it intact.
        assertThrows(VaultRequestException.class, () -> cache.decrypt("item", new byte[16]));

        assertEquals(List.of(longToken), vault.tokens());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', quoteCharacter = '`', value = {
            "503|{\"errors\":[\"Vault is sealed\"]}",
            "429|{\"errors\":[\"request path \\\"secret/data/item\\\": rate limit quota exceeded\"]}",
            "500|{\"errors\":[\"internal error\"]}",
            "502|<html>Bad Gateway</html>",
            "504|``",
    })
    void aTransientAnswer_IsRetried_UntilVaultAnswers(int status, String body) {
        var tokens = new FakeTokenProvider();
        var cache = create(options -> {
        }, tokens);
        vault.set("item", "value");
        vault.answer = new Answer(status, body);
        vault.onRead = exchange -> {
            if (vault.reads().size() == 3)
                vault.answer = null;
        };

        assertEquals("value", decryptString(cache, "item"));

        assertEquals(3, vault.reads().size());
        assertEquals(1, tokens.calls());
    }

    @ParameterizedTest
    @ValueSource(ints = {HashiCorpVaultSecretCacheOptions.MIN_RETRY_COUNT, HashiCorpVaultSecretCacheOptions.MAX_RETRY_COUNT})
    void aTransientAnswer_IsRetriedRetryCountTimes_ThenPropagates(int retryCount) {
        var cache = create(options -> options.retryCount(retryCount));
        vault.answer = new Answer(503, "{\"errors\":[\"Vault is sealed\"]}");

        var e = assertThrows(VaultRequestException.class, () -> cache.decrypt("item", new byte[16]));

        assertEquals(503, e.statusCode());
        assertEquals(1 + retryCount, vault.reads().size());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', quoteCharacter = '`', value = {
            "403|{\"errors\":[\"permission denied\"]}",
            "404|{\"errors\":[\"no handler for route\"]}",
            "400|{\"errors\":[\"bad request\"]}",
            "501|{\"errors\":[\"unsupported operation\"]}",
            "307|``",
    })
    void anAnswerThatWouldRepeat_IsNotRetried(int status, String body) {
        var cache = create();
        vault.answer = new Answer(status, body);

        assertThrows(VaultRequestException.class, () -> cache.decrypt("item", new byte[16]));

        assertEquals(1, vault.reads().size());
    }

    enum LostConnection { NO_ANSWER, DROPPED_MID_RESPONSE, ATTEMPT_TIMED_OUT }

    @ParameterizedTest
    @EnumSource(LostConnection.class)
    void aLostConnection_IsRetried(LostConnection how) {
        var cache = create(options -> options.timeout(Duration.ofMillis(300)));
        vault.set("item", "value");
        vault.onRead = exchange -> {
            if (vault.reads().size() > 2)
                return;

            switch (how) {
                case NO_ANSWER -> throw new IOException("The connection is dropped without an answer.");
                case DROPPED_MID_RESPONSE -> {
                    exchange.sendResponseHeaders(200, 200);
                    exchange.getResponseBody().write("{\"data\":{\"data\":{\"value\":\"val".getBytes(StandardCharsets.UTF_8));
                    exchange.getResponseBody().flush();
                    throw new IOException("The connection is dropped mid-response.");
                }
                case ATTEMPT_TIMED_OUT -> sleepQuietly(1_000);
            }
        };

        assertEquals("value", decryptString(cache, "item"));
        assertEquals(3, vault.reads().size());
    }

    @Test
    void aBodyThatStalls_TimesOutWithinTheAttemptsTimeout_AndIsRetried() {
        var cache = create(options -> options.timeout(Duration.ofMillis(300)));
        vault.onRead = exchange -> {
            exchange.sendResponseHeaders(200, 0);
            exchange.getResponseBody().write("{\"data\":{\"data\":{\"value\":\"val".getBytes(StandardCharsets.UTF_8));
            exchange.getResponseBody().flush();
            sleepQuietly(5_000);
            throw new IOException("Never finished.");
        };

        var started = System.nanoTime();
        var e = assertThrows(UncheckedIOException.class, () -> cache.decrypt("item", new byte[16]));
        var elapsed = Duration.ofNanos(System.nanoTime() - started);

        assertInstanceOf(HttpTimeoutException.class, e.getCause());
        assertEquals(1 + HashiCorpVaultSecretCacheOptions.MIN_RETRY_COUNT, vault.reads().size());
        // Four attempts of 300 ms and three waits of at most 100 ms, far short of one stalled body.
        assertTrue(elapsed.compareTo(Duration.ofMillis(4_000)) < 0, elapsed.toString());
    }

    @Test
    void anUnreachableVault_IsRetried_ThenPropagatesTheIOException() throws IOException {
        int port;
        try (var socket = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            port = socket.getLocalPort();
        }
        var cache = create(vault, URI.create("http://127.0.0.1:" + port + "/"), options -> {
        }, null, null);

        var e = assertThrows(UncheckedIOException.class, () -> cache.decrypt("item", new byte[16]));

        assertInstanceOf(IOException.class, e.getCause());
    }

    @Test
    void aTokenProviderFailure_IsNotRetried_AndPropagatesAsItIs() {
        var tokens = new FakeTokenProvider();
        var failure = new IllegalStateException("The login endpoint is unreachable.");
        tokens.next = call -> CompletableFuture.failedFuture(failure);
        var cache = create(options -> {
        }, tokens);

        var e = assertThrows(IllegalStateException.class, () -> cache.decrypt("item", new byte[16]));

        assertSame(failure, e);
        assertEquals(1, tokens.calls());
        assertEquals(List.of(), vault.reads());
    }

    @Test
    void aTokenProviderThatThrows_PropagatesAsItIs() {
        var tokens = new FakeTokenProvider();
        tokens.next = call -> {
            throw new IllegalArgumentException("Misconfigured.");
        };
        var cache = create(options -> {
        }, tokens);

        assertThrows(IllegalArgumentException.class, () -> cache.decrypt("item", new byte[16]));
        assertEquals(List.of(), vault.reads());
    }

    @Test
    void aTokenProvidersCheckedIOException_PropagatesAsUncheckedIOException() {
        var tokens = new FakeTokenProvider();
        tokens.next = call -> CompletableFuture.failedFuture(new IOException("The token file can't be read."));
        var cache = create(options -> {
        }, tokens);

        var e = assertThrows(UncheckedIOException.class, () -> cache.decrypt("item", new byte[16]));

        assertEquals("The token file can't be read.", e.getCause().getMessage());
        assertEquals(List.of(), vault.reads());
    }

    @Test
    void aProviderSlowerThanTheTimeout_IsCancelled() {
        var tokens = new FakeTokenProvider(true);
        tokens.next = call -> new CompletableFuture<>();
        var cache = create(options -> options.timeout(Duration.ofMillis(100)), tokens);

        assertThrows(CancellationException.class, () -> cache.decrypt("item", new byte[16]));

        assertTrue(tokens.lastGiven.isCancelled());
        assertEquals(List.of(), vault.reads());
    }

    @ParameterizedTest
    @CsvSource({
            "200, 0, 0, 200",
            "200, 1, 0, 400",
            "200, 2, 0, 800",
            "200, 5, 0, 6400",
            "200, 6, 0, 10000",
            "200, 9, 0, 10000",
            "200, 0, 100, 300",
            "200, 9, 100, 10100",
            "0, 3, 37, 37",
            "10000, 0, 0, 10000",
            "10000, 40, 0, 10000",
    })
    void retryDelay_Doubles_UpToTheMaximum_PlusTheJitter(int baseMillis, int retry, int jitter, int expectedMillis) {
        assertEquals(Duration.ofMillis(expectedMillis), HashiCorpVaultSecretCacheImpl.retryDelay(Duration.ofMillis(baseMillis), retry, jitter));
    }

    @Test
    void theRetryOptions_AreChecked() {
        assertThrows(IllegalArgumentException.class, () -> newCache(options().retryCount(HashiCorpVaultSecretCacheOptions.MIN_RETRY_COUNT - 1)));
        assertThrows(IllegalArgumentException.class, () -> newCache(options().retryCount(HashiCorpVaultSecretCacheOptions.MAX_RETRY_COUNT + 1)));
        assertThrows(IllegalArgumentException.class, () -> newCache(options().retryDelay(Duration.ofMillis(-1))));
        assertThrows(IllegalArgumentException.class,
                () -> newCache(options().retryDelay(HashiCorpVaultSecretCacheOptions.MAX_RETRY_DELAY.plusNanos(1))));

        newCache(options().retryCount(HashiCorpVaultSecretCacheOptions.MIN_RETRY_COUNT).retryDelay(Duration.ZERO));
        newCache(options().retryCount(HashiCorpVaultSecretCacheOptions.MAX_RETRY_COUNT).retryDelay(HashiCorpVaultSecretCacheOptions.MAX_RETRY_DELAY));
    }

    @Test
    void aValueWithJsonEscapes_IsUnescapedExactly() {
        var cache = create();
        var secret = "p\"a\\ss/wörd\n\u0001秘密";
        vault.set("escaped", secret);

        assertEquals(secret, decryptString(cache, "escaped"));
    }

    @Test
    void aLargeSecret_RoundTrips() {
        var cache = create();
        var large = "é-秘密-".repeat(1500);
        vault.set("large", large);

        var max = cache.findMaxDecryptedLength("large").orElseThrow();
        var result = new char[max];
        assertEquals(large, new String(result, 0, cache.decrypt("large", result)));
    }

    @Test
    void pathsDifferingOnlyInCase_AreDifferentSecrets_AndDifferentEntries() {
        var cache = create();
        vault.set("myapp/Db", "upper");
        vault.set("myapp/db", "lower");

        assertEquals("upper", decryptString(cache, "myapp/Db"));
        assertEquals("lower", decryptString(cache, "myapp/db"));
        assertEquals(0, cache.decrypt("MYAPP/DB", new byte[16]));
        assertEquals("upper", decryptString(cache, "myapp/Db"));

        assertEquals(List.of("myapp/Db", "myapp/db", "MYAPP/DB"), vault.reads());
    }

    @Test
    void aMissingSecret_ReturnsZero_AndIsLookedUpAgainUntilItExists() {
        var cache = create();

        assertEquals(0, cache.decrypt("later", new byte[16]));
        assertTrue(cache.findMaxDecryptedLength("later").isEmpty());

        vault.set("later", "now here");
        assertEquals("now here", decryptString(cache, "later"));
        assertEquals(3, vault.reads().size());
    }

    @Test
    void aDeletedLatestVersion_IsReportedMissing() {
        var cache = create();
        vault.setDeleted("gone");

        assertEquals(0, cache.decrypt("gone", new byte[16]));
    }

    @Test
    void numbersAndBooleans_AreCachedAsTheirText_AndOtherValuesAreMissing() {
        var cache = create();
        vault.setData("item", FakeVault.Json.object(
                "number", 5432, "flag", true, "empty", "", "object", Map.of("value", "nested"), "array", List.of("x"), "null", null));

        assertEquals("5432", decryptString(cache, "item#number"));
        assertEquals("true", decryptString(cache, "item#flag"));
        for (var key : List.of("absent", "empty", "object", "array", "null", "value"))
            assertEquals(0, cache.decrypt("item#" + key, new byte[16]), key);
    }

    @Test
    void aDuplicatedKey_IsRefused() {
        var cache = create();
        vault.answer = new Answer(200, "{\"data\":{\"data\":{\"k\":\"a\",\"k\":\"b\"}}}");

        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item#k", new byte[16]));
    }

    @ParameterizedTest
    @ValueSource(strings = {"not json", "[\"value\"]", "{\"data\":{\"data\":{\"value\":\"a\",\"value\":\"b\"}}}", ""})
    void aResponseThatCantBeTrusted_IsRefused_AndNotRetried(String body) {
        var cache = create();
        vault.answer = new Answer(200, body);

        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));
        assertEquals(1, vault.reads().size());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', quoteCharacter = '`', value = {
            "404|{\"errors\":[\"no handler for route \\\"nope/data/item\\\". route entry not found.\"]}|no handler for route",
            "404|<html>Not Found</html>|HTTP 404",
            "503|{\"errors\":[\"Vault is sealed\"]}|Vault is sealed",
            "500|[\"internal\"]|HTTP 500",
            "500|{\"errors\":\"internal\"}|HTTP 500",
            "307|``|HTTP 307",
            "502|{\"request_id\":\"x\"}|HTTP 502",
    })
    void anyOtherAnswer_Propagates_WithVaultsStatusAndErrors(int status, String body, String expected) {
        var cache = create();
        vault.answer = new Answer(status, body);

        var e = assertThrows(VaultRequestException.class, () -> cache.decrypt("item", new byte[16]));
        assertEquals(status, e.statusCode());
        assertTrue(e.getMessage().contains(expected), e.getMessage());
        assertTrue(e.getMessage().contains("'item'"), e.getMessage());
        assertFalse(e.getMessage().contains(FakeVault.TOKEN));

        vault.answer = null;
        vault.set("item", "value");
        assertEquals("value", decryptString(cache, "item"));
    }

    @Test
    void aRedirect_IsNotFollowed() {
        var cache = create();
        vault.set("elsewhere", "value");
        vault.answer = new Answer(307, "", Map.of("Location", vault.readUri("elsewhere").toString()));

        var e = assertThrows(VaultRequestException.class, () -> cache.decrypt("item", new byte[16]));

        assertEquals(307, e.statusCode());
        assertEquals(List.of("item"), vault.reads());
    }

    @Test
    void aClientThatFollowsRedirects_WhenAllowed_SendsTheTokenAlongTheRedirect() {
        var client = track(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build());
        var cache = create(options -> options.httpClient(client).allowRedirects(true));
        vault.set("elsewhere", "value");
        vault.onRead = exchange -> vault.answer = exchange.getRequestURI().getPath().endsWith("/item")
                ? new Answer(307, "", Map.of("Location", vault.readUri("elsewhere").toString()))
                : null;

        // The redirect target's secret is cached as item's...
        assertEquals("value", decryptString(cache, "item"));

        // ...and, what allowRedirects means, the redirect target saw the token too.
        assertEquals(List.of("item", "elsewhere"), vault.reads());
        assertEquals(List.of(FakeVault.TOKEN, FakeVault.TOKEN), vault.tokens());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "", "ConnectionStrings:Admin", "../sys/seal-status", "myapp/../other", "myapp/./db", "..", "/leading", "trailing/",
            "double//slash", "has space", "café", "bang!", "query?list=true", "percent%2F", "item#", "#key", "item#a#b", "item#a b",
            "item#bang!",
    })
    void aNameThatIsntAPathAndKey_IsMissing_WithoutCallingVault(String name) {
        var cache = create();

        assertEquals(0, cache.decrypt(name, new byte[16]));
        assertEquals(0, cache.decrypt(name, new char[16]));
        assertTrue(cache.findMaxDecryptedLength(name).isEmpty());
        assertEquals(List.of(), vault.reads());
        assertEquals(List.of(), vault.unexpectedRequests());
    }

    @Test
    void isValidSecretName_AcceptsPathsAndKeys_UpToTheLimit() {
        assertTrue(HashiCorpVaultSecretCacheImpl.isValidSecretName("a"));
        assertTrue(HashiCorpVaultSecretCacheImpl.isValidSecretName("team-a/my_app/db.v2"));
        assertTrue(HashiCorpVaultSecretCacheImpl.isValidSecretName("...x/x.."));
        assertFalse(HashiCorpVaultSecretCacheImpl.isValidSecretName("myapp/db#password"));
        assertTrue(HashiCorpVaultSecretCacheImpl.isValidSecretName("x".repeat(HashiCorpVaultSecretCacheImpl.MAX_SECRET_NAME_LENGTH)));
        assertFalse(HashiCorpVaultSecretCacheImpl.isValidSecretName("x".repeat(HashiCorpVaultSecretCacheImpl.MAX_SECRET_NAME_LENGTH + 1)));
        assertFalse(HashiCorpVaultSecretCacheImpl.isValidSecretName(null));
    }

    @Test
    void aCachedSecret_StillDecryptsAfterTheRingRotates() {
        var ring = ring();
        var cache = newCache(vault.address(), ring, null);
        vault.set("before", "v1 value");
        vault.set("after", "v2 value");

        assertEquals("v1 value", decryptString(cache, "before"));
        ring.add(2, TestRings.newKey());

        assertEquals("v2 value", decryptString(cache, "after"));
        assertEquals("v1 value", decryptString(cache, "before"));
    }

    @Test
    void inACollection_OnlyNamesTheEarlierSourcesMiss_ReachVault() {
        var vaultCache = create();
        vault.set("from-vault", "vault value");
        var local = new ProtectedCacheImpl(ring());
        local.add("ConnectionStrings:Admin", "local value".toCharArray());
        var collection = new ProtectedCacheCollectionImpl().add(local).add(vaultCache);

        assertEquals("local value", decryptString(collection, "ConnectionStrings:Admin"));
        assertEquals("vault value", decryptString(collection, "from-vault"));
        assertEquals(List.of("from-vault"), vault.reads());
    }

    @Test
    void withSensitiveLogging_AFetchLogsTheNameOnly_AndAFailureLogsAnError() {
        var logger = new RecordingLogger();
        var cache = create(vault, vault.address(), options -> {
        }, null, logger);
        vault.set("myapp/Item", "never-logged");

        TestRings.withSensitiveLogging(() -> {
            assertEquals("never-logged", decryptString(cache, "myapp/Item"));
            vault.answer = new Answer(503, "{\"errors\":[\"Vault is sealed\"]}");
            assertThrows(VaultRequestException.class, () -> cache.decrypt("other", new byte[16]));
        });

        // The secret's own name, not its escaped entry name.
        var entries = logger.entries();
        assertTrue(entries.stream().anyMatch(e -> e.level() == Level.DEBUG
                && Integer.valueOf(HkdfGuardLog.SENSITIVE_OPERATION_LOGGED).equals(e.eventId()) && e.message().contains("myapp/Item")));
        assertTrue(entries.stream().anyMatch(e -> e.level() == Level.ERROR && e.exception() instanceof VaultRequestException));
        assertTrue(entries.stream().noneMatch(e -> e.message().contains("never-logged") || e.message().contains(FakeVault.TOKEN)));
    }

    @Test
    void close_LeavesASuppliedClientUsable() throws Exception {
        var client = track(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build());
        var cache = create(options -> options.httpClient(client));
        vault.set("item", "value");
        assertEquals("value", decryptString(cache, "item"));
        cache.close();

        var request = HttpRequest.newBuilder(vault.readUri("item"))
                .header("X-Vault-Request", "true")
                .header("X-Vault-Token", FakeVault.TOKEN)
                .build();
        assertEquals(200, client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode());
    }

    @Test
    void afterClose_CachedSecretsAreServed_ButNothingIsRead() {
        var cache = create();
        vault.set("item", "value");
        vault.set("other", "value");
        assertEquals("value", decryptString(cache, "item"));

        cache.close();
        cache.close();

        assertEquals("value", decryptString(cache, "item"));
        assertThrows(IllegalStateException.class, () -> cache.decrypt("other", new byte[16]));
        assertEquals(List.of("item"), vault.reads());
    }

    @Test
    void theDefaults_MakeNoCallUntilASecretIsRequested() {
        var cache = newCache(URI.create("http://127.0.0.1:8200"), ring(), null);

        assertEquals(0, cache.decrypt("not:a:path", new byte[16]));
    }

    @Test
    void theDefaults_AreVaultsOwn() {
        var defaults = HashiCorpVaultSecretCacheOptions.builder().build();

        assertEquals("secret", defaults.mountPath());
        assertEquals(VaultKvVersion.V2, defaults.kvVersion());
        assertEquals("value", defaults.defaultKey());
        assertNull(defaults.namespace());
        assertEquals(Duration.ofSeconds(30), defaults.timeout());
        assertEquals(3, defaults.retryCount());
        assertEquals(Duration.ofMillis(200), defaults.retryDelay());
        assertNull(defaults.httpClient());
        assertFalse(defaults.allowRedirects());

        var changed = defaults.toBuilder().namespace("team-a").build();
        assertEquals("team-a", changed.namespace());
        assertEquals("secret", changed.mountPath());
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://localhost:8200", "http://127.0.0.1:8200", "http://127.1.2.3", "http://[::1]:8200",
            "https://vault.example.com:8200", "HTTPS://vault.example.com/prefix/"})
    void theConstructor_AcceptsHttps_AndHttpOnlyOnLoopback(String address) {
        newCache(URI.create(address), ring(), null);
    }

    @ParameterizedTest
    @ValueSource(strings = {"relative/path", "vault.test:8200", "http://vault.example.com:8200", "http://10.0.0.1:8200", "http://[::2]",
            "ftp://127.0.0.1", "https://user:pass@vault.example.com", "https://vault.example.com/?x=1", "https://vault.example.com/#frag",
            "https:///no-host"})
    void theConstructor_RejectsAnAddressThatWouldExposeTheToken(String address) {
        var ring = ring();
        var uri = URI.create(address);

        assertThrows(IllegalArgumentException.class, () -> newCache(uri, ring, null));
    }

    @Test
    void theConstructor_RejectsInvalidOptions() {
        var ring = ring();
        var protector = ring.createProtector(TOKEN_PURPOSE);
        var token = StaticVaultToken.protect(protector, FakeVault.TOKEN);
        var address = vault.address();

        assertThrows(NullPointerException.class, () -> new HashiCorpVaultSecretCacheImpl(null, token, protector, ring, null, null));
        assertThrows(NullPointerException.class, () -> new HashiCorpVaultSecretCacheImpl(address, null, protector, ring, null, null));
        assertThrows(NullPointerException.class, () -> new HashiCorpVaultSecretCacheImpl(address, token, null, ring, null, null));
        assertThrows(NullPointerException.class, () -> new HashiCorpVaultSecretCacheImpl(address, token, protector, null, null, null));
        assertThrows(IllegalArgumentException.class, () -> newCache(options().mountPath("")));
        assertThrows(IllegalArgumentException.class, () -> newCache(options().mountPath("../sys")));
        assertThrows(IllegalArgumentException.class, () -> newCache(options().mountPath(null)));
        assertThrows(IllegalArgumentException.class, () -> newCache(options().defaultKey("")));
        assertThrows(IllegalArgumentException.class, () -> newCache(options().defaultKey("a b")));
        assertThrows(IllegalArgumentException.class, () -> newCache(options().defaultKey(null)));
        assertThrows(IllegalArgumentException.class, () -> newCache(options().namespace("team a")));
        assertThrows(IllegalArgumentException.class, () -> newCache(options().timeout(Duration.ZERO)));
        assertThrows(IllegalArgumentException.class, () -> newCache(options().timeout(Duration.ofMillis(-1))));
        assertThrows(NullPointerException.class, () -> options().kvVersion(null));
        assertThrows(NullPointerException.class, () -> options().timeout(null));
        assertThrows(NullPointerException.class, () -> options().retryDelay(null));
    }

    @ParameterizedTest
    @EnumSource(value = HttpClient.Redirect.class, names = {"NORMAL", "ALWAYS"})
    void aClientThatFollowsRedirects_IsRefused(HttpClient.Redirect redirect) {
        var client = track(HttpClient.newBuilder().followRedirects(redirect).build());

        var e = assertThrows(IllegalArgumentException.class, () -> newCache(options().httpClient(client)));
        assertTrue(e.getMessage().contains("allowRedirects"));
    }

    @Test
    void aClientThatFollowsNoRedirects_IsAccepted() {
        var client = track(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build());

        assertEquals(0, newCache(options().httpClient(client)).decrypt("not:a:path", new byte[16]));
    }

    @ParameterizedTest
    @EnumSource(value = HttpClient.Redirect.class, names = {"NORMAL", "ALWAYS"})
    void aClientThatFollowsRedirects_IsAccepted_WhenExplicitlyAllowed(HttpClient.Redirect redirect) {
        var client = track(HttpClient.newBuilder().followRedirects(redirect).build());

        assertEquals(0, newCache(options().httpClient(client).allowRedirects(true)).decrypt("not:a:path", new byte[16]));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "hvs.with space", "hvs.line\nbreak", "café"})
    void staticVaultToken_Protect_RejectsATokenThatCantBeSent(String token) {
        var protector = ring().createProtector(TOKEN_PURPOSE);

        assertThrows(IllegalArgumentException.class, () -> StaticVaultToken.protect(protector, token));
    }

    @Test
    void staticVaultToken_Protect_RejectsNulls() {
        var protector = ring().createProtector(TOKEN_PURPOSE);

        assertThrows(NullPointerException.class, () -> StaticVaultToken.protect(null, FakeVault.TOKEN));
        assertThrows(NullPointerException.class, () -> StaticVaultToken.protect(protector, null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " "})
    void staticVaultToken_RejectsAnEmptyProtectedToken(String protectedToken) {
        assertThrows(IllegalArgumentException.class, () -> new StaticVaultToken(protectedToken));
        assertThrows(NullPointerException.class, () -> new StaticVaultToken(null));
    }

    @Test
    void staticVaultToken_Protect_HoldsOnlyTheProtectedToken() {
        var protector = ring().createProtector(TOKEN_PURPOSE);
        var token = FakeVault.TOKEN.toCharArray();

        var held = await(StaticVaultToken.protect(protector, java.nio.CharBuffer.wrap(token)).getTokenAsync());

        assertFalse(held.contains(FakeVault.TOKEN));
        var revealed = new char[64];
        assertEquals(FakeVault.TOKEN, new String(revealed, 0, protector.decrypt(held, revealed)));
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static boolean eventually(java.util.function.BooleanSupplier condition) throws InterruptedException {
        var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline)
                return false;
            Thread.sleep(20);
        }
        return true;
    }
}
