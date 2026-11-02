package io.github.runsecure.hkdfguard.cache.azurekeyvault;

import static io.github.runsecure.hkdfguard.cache.azurekeyvault.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.cache.azurekeyvault.Futures.await;
import static io.github.runsecure.hkdfguard.cache.azurekeyvault.TestRings.text;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.azure.core.exception.ClientAuthenticationException;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpPipelineBuilder;
import com.azure.core.http.HttpResponse;
import com.azure.core.http.policy.HttpLogDetailLevel;
import com.azure.core.http.policy.HttpLogOptions;
import com.azure.core.http.policy.HttpResponseLogger;
import com.azure.core.http.policy.HttpResponseLoggingContext;
import com.azure.core.util.logging.ClientLogger;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheCollectionImpl;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.event.Level;
import reactor.core.publisher.Mono;

/** A real SecretClient, with the cache's own pipeline policy, over a stub Key Vault HTTP client. */
class AzureKeyVaultSecretCacheImplTest {
    // A key/value secret as AWS Secrets Manager's console stores one.
    private static final String KEY_VALUE_SECRET = """
            {
              "test-credential-1": "This is my first credential",
              "service-credential-3": "This is my third credential",
              "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
              "domain-credential-17": "fakedomain/thiscredential",
              "port": 5432
            }""";

    private final KeyRingImpl ring = TestRings.ring();
    private final SecretsHttpStub vault = new SecretsHttpStub();

    @AfterEach
    void closeRing() {
        ring.close();
    }

    private AzureKeyVaultSecretCacheImpl create() {
        return new AzureKeyVaultSecretCacheImpl(vault.builder(), ring);
    }

    private static String decryptString(ProtectedReadOnlyCache cache, String name) {
        var result = new char[512];
        return new String(result, 0, cache.decrypt(name, result));
    }

    @Test
    void decrypt_OnMiss_FetchesTheOneSecret_ThenServesItFromTheCache() {
        var cache = create();
        vault.set("Db-Password", "s3cret");

        assertEquals("s3cret", decryptString(cache, "Db-Password"));
        var bytes = new byte[64];
        assertEquals("s3cret", text(bytes, cache.decrypt("Db-Password", bytes)));

        assertEquals(List.of("Db-Password"), vault.gets);
        assertTrue(vault.unexpectedRequests.isEmpty());
    }

    @Test
    void aJsonSecret_IsCachedWholeAndByKey_FromOneCall_AndSecretClientNeverSeesIt() {
        var cache = create();
        vault.set("App-Credentials", KEY_VALUE_SECRET);

        assertEquals("0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
                decryptString(cache, "App-Credentials#api-credential-21"));
        assertEquals("This is my first credential", decryptString(cache, "app-credentials#test-credential-1"));
        assertEquals("fakedomain/thiscredential", decryptString(cache, "APP-CREDENTIALS#domain-credential-17"));
        assertEquals("5432", decryptString(cache, "App-Credentials#port"));
        assertEquals(KEY_VALUE_SECRET, decryptString(cache, "App-Credentials"));

        // Secret names ignore case; keys don't.
        assertEquals(0, cache.decrypt("App-Credentials#PORT", new byte[16]));

        assertEquals(List.of("App-Credentials", "App-Credentials"), vault.gets);
        assertFalse(vault.bodiesSeenBySecretClient.isEmpty());
        assertTrue(vault.bodiesSeenBySecretClient.stream().noneMatch(body -> body.contains("credential")));
    }

    @Test
    void decryptAsync_Fetches_AndSecretClientNeverSeesTheValue() {
        var cache = create();
        vault.set("App-Credentials", KEY_VALUE_SECRET);

        var chars = new char[512];
        assertEquals("fakedomain/thiscredential", new String(chars, 0, await(cache.decryptAsync("App-Credentials#domain-credential-17", chars))));
        assertEquals(KEY_VALUE_SECRET, new String(chars, 0, await(cache.decryptAsync("app-credentials", chars))));
        assertEquals(0, await(cache.decryptAsync("Missing", new byte[16])));
        assertTrue(await(cache.findMaxDecryptedLengthAsync("Not:Valid")).isEmpty());

        assertEquals(List.of("App-Credentials", "Missing"), vault.gets);
        assertFalse(vault.bodiesSeenBySecretClient.isEmpty());
        assertTrue(vault.bodiesSeenBySecretClient.stream().noneMatch(body -> body.contains("credential")));
    }

    @Test
    void decryptAsync_PropagatesAKeyVaultFailure() {
        var cache = create();
        vault.set("Item", "value");
        vault.failWith = 403;

        var e = assertFailsWith(HttpResponseException.class, cache.decryptAsync("Item", new byte[16]));
        assertEquals(403, e.getResponse().getStatusCode());
    }

    @Test
    void cancellingAnAsyncLookup_InterruptsTheFetch_AndTheNextLookupFetchesAgain() throws InterruptedException {
        var cache = create();
        vault.set("slow", "value");
        var entered = new CountDownLatch(1);
        var interrupted = new CountDownLatch(1);
        vault.onGet = () -> {
            entered.countDown();
            try {
                new CountDownLatch(1).await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                interrupted.countDown();
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted.", e);
            }
        };

        var lookup = cache.decryptAsync("slow", new byte[16]);
        assertTrue(entered.await(10, TimeUnit.SECONDS));
        assertTrue(lookup.cancel(true));

        assertTrue(interrupted.await(10, TimeUnit.SECONDS));
        assertThrows(CancellationException.class, lookup::join);

        vault.onGet = null;
        assertEquals("value", decryptString(cache, "slow"));
        assertEquals(List.of("slow", "slow"), vault.gets);
    }

    @Test
    void anotherClient_SharingTheBuilder_IsLeftAlone() {
        var builder = vault.builder();
        new AzureKeyVaultSecretCacheImpl(builder, ring);
        vault.set("Db-Password", "s3cret");

        // The cache's policy is now in this builder too, but acts only inside the cache's own fetch.
        assertEquals("s3cret", builder.buildClient().getSecret("Db-Password").getValue());
        assertEquals("s3cret", builder.buildAsyncClient().getSecret("Db-Password").block().getValue());
    }

    @Test
    void secretClient_IsOnlyEverGivenTheBodyWithTheValueBlanked() {
        var cache = create();
        vault.set("Db-Password", "s3cret");

        assertEquals("s3cret", decryptString(cache, "Db-Password"));

        assertEquals(1, vault.bodiesSeenBySecretClient.size());
        var body = vault.bodiesSeenBySecretClient.get(0);
        assertFalse(body.contains("s3cret"));
        assertTrue(body.contains("\"value\":\"\""));
        // Only the top-level value is taken: a nested property of the same name is left alone.
        assertTrue(body.contains("a tag, not the secret"));
    }

    @Test
    void theCachesFetches_AskForTheBodyUnbuffered() {
        var cache = create();
        vault.set("Db-Password", "s3cret");

        assertEquals("s3cret", decryptString(cache, "Db-Password"));
        assertEquals(List.of(false), vault.eagerReads);
        assertTrue(vault.bufferedBodies.isEmpty());
    }

    @Test
    void aBodyTheHttpClientBufferedAnyway_IsZeroedOnceCaptured() {
        var cache = create();
        vault.set("Db-Password", "s3cret");
        vault.alwaysBuffer = true;

        assertEquals("s3cret", decryptString(cache, "Db-Password"));

        assertEquals(1, vault.bufferedBodies.size());
        assertArrayEquals(new byte[vault.bufferedBodies.get(0).length], vault.bufferedBodies.get(0));
        assertFalse(vault.bodiesSeenBySecretClient.get(0).contains("s3cret"));
    }

    @Test
    void aValueWithJsonEscapes_IsUnescapedExactly() {
        var cache = create();
        var secret = "p\"a\\ss/wörd\n\u0001秘密";
        vault.set("escaped", secret);

        assertEquals(secret, decryptString(cache, "escaped"));
        assertFalse(vault.bodiesSeenBySecretClient.get(0).contains("wörd"));
    }

    @Test
    void findMaxDecryptedLength_OnMiss_FetchesTheSecret() {
        var cache = create();
        vault.set("api-key", "value");

        assertTrue(cache.findMaxDecryptedLength("api-key").orElseThrow() >= 5);
        assertEquals("value", decryptString(cache, "api-key"));
        assertEquals(1, vault.gets.size());
    }

    @Test
    void namesDifferingInCase_AreOneEntry_AndOneFetch() {
        var cache = create();
        vault.set("Db-Password", "s3cret");

        assertEquals("s3cret", decryptString(cache, "db-password"));
        assertEquals("s3cret", decryptString(cache, "DB-PASSWORD"));
        assertEquals(List.of("db-password"), vault.gets);
    }

    @Test
    void aMissingSecret_ReturnsZero_AndIsLookedUpAgainUntilItExists() {
        var cache = create();

        assertEquals(0, cache.decrypt("later", new byte[16]));
        assertTrue(cache.findMaxDecryptedLength("later").isEmpty());

        vault.set("later", "now here");
        assertEquals("now here", decryptString(cache, "later"));
        assertEquals(3, vault.gets.size());
    }

    @Test
    void anEmptySecret_IsReportedMissing() {
        var cache = create();
        vault.set("empty", "");

        assertEquals(0, cache.decrypt("empty", new byte[16]));
        assertEquals(1, vault.gets.size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "ConnectionStrings:Admin", "db_password", "../keys/other", "name/version", "name?api-version=1", "café", "has space"})
    void aNameKeyVaultCantHold_IsMissing_WithoutCallingTheVault(String name) {
        var cache = create();

        assertEquals(0, cache.decrypt(name, new byte[16]));
        assertEquals(0, cache.decrypt(name, new char[16]));
        assertTrue(cache.findMaxDecryptedLength(name).isEmpty());
        assertEquals(0, await(cache.decryptAsync(name, new byte[16])));
        assertTrue(vault.gets.isEmpty());
        assertTrue(vault.unexpectedRequests.isEmpty());
    }

    @Test
    void isValidSecretName_AcceptsLettersDigitsAndHyphens_UpTo127() {
        assertTrue(AzureKeyVaultSecretCacheImpl.isValidSecretName("a"));
        assertTrue(AzureKeyVaultSecretCacheImpl.isValidSecretName("Db-Password-2"));
        assertTrue(AzureKeyVaultSecretCacheImpl.isValidSecretName("x".repeat(AzureKeyVaultSecretCacheImpl.MAX_SECRET_NAME_LENGTH)));
        assertFalse(AzureKeyVaultSecretCacheImpl.isValidSecretName("x".repeat(AzureKeyVaultSecretCacheImpl.MAX_SECRET_NAME_LENGTH + 1)));
        assertFalse(AzureKeyVaultSecretCacheImpl.isValidSecretName(""));
        assertFalse(AzureKeyVaultSecretCacheImpl.isValidSecretName(null));
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 403, 429, 500, 503})
    void aVaultFailure_Propagates_AndIsRetriedOnTheNextLookup(int status) {
        var cache = create();
        vault.set("item", "value");
        vault.failWith = status;

        var thrown = assertThrows(HttpResponseException.class, () -> cache.decrypt("item", new byte[16]));
        assertEquals(status, thrown.getResponse().getStatusCode());

        vault.failWith = null;
        assertEquals("value", decryptString(cache, "item"));
        assertEquals(2, vault.gets.size());
    }

    @Test
    void aResponseThatIsNotJson_IsRefused() {
        var cache = create();
        vault.rawBody = "not json";

        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));
    }

    @Test
    void aCredentialFailure_Propagates() {
        var builder = vault.builder().credential(request -> Mono.error(new ClientAuthenticationException("no token", null)));
        var cache = new AzureKeyVaultSecretCacheImpl(builder, ring);

        assertThrows(ClientAuthenticationException.class, () -> cache.decrypt("item", new char[16]));
        assertTrue(vault.gets.isEmpty());
    }

    @Test
    void concurrentMissesOnOneName_ShareOneFetch() throws InterruptedException {
        var cache = create();
        vault.set("shared", "value");
        var release = new CountDownLatch(1);
        vault.onGet = () -> {
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };

        var lookups = new ArrayList<CompletableFuture<String>>();
        for (var i = 0; i < 8; i++)
            lookups.add(CompletableFuture.supplyAsync(() -> decryptString(cache, "shared")));
        Futures.sleep(200);
        release.countDown();

        for (var lookup : lookups)
            assertEquals("value", await(lookup));
        assertEquals(1, vault.gets.size());
    }

    @Test
    void aLargeSecret_RoundTrips() {
        var cache = create();
        var large = "é-秘密-".repeat(3000);
        assertTrue(large.getBytes(StandardCharsets.UTF_8).length > 16 * 1024);
        vault.set("large", large);

        var result = new char[cache.findMaxDecryptedLength("large").orElseThrow()];
        assertEquals(large, new String(result, 0, cache.decrypt("large", result)));
    }

    @Test
    void aCachedSecret_StillDecryptsAfterTheRingRotates() {
        var cache = create();
        vault.set("before", "v1 value");
        vault.set("after", "v2 value");

        assertEquals("v1 value", decryptString(cache, "before"));
        ring.add(2, TestRings.newKey());

        assertEquals("v2 value", decryptString(cache, "after"));
        assertEquals("v1 value", decryptString(cache, "before"));
    }

    @Test
    void inACollection_OnlyNamesTheEarlierSourcesMiss_ReachTheVault() {
        var vaultCache = create();
        vault.set("from-vault", "vault value");
        var local = new ProtectedCacheImpl(ring);
        local.add("ConnectionStrings:Admin", "local value".toCharArray());
        var collection = new ProtectedCacheCollectionImpl().add(local).add(vaultCache);

        assertEquals("local value", decryptString(collection, "ConnectionStrings:Admin"));
        assertEquals("vault value", decryptString(collection, "from-vault"));
        assertEquals(List.of("from-vault"), vault.gets);
    }

    @Test
    void withSensitiveLogging_AFetchLogsTheNameOnly_AndAFailureLogsAnError() {
        var logger = new RecordingLogger();
        var cache = new AzureKeyVaultSecretCacheImpl(vault.builder(), ring, logger);
        vault.set("item", "never-logged");

        TestRings.withSensitiveLogging(() -> {
            assertEquals("never-logged", decryptString(cache, "item"));
            vault.failWith = 500;
            assertThrows(HttpResponseException.class, () -> cache.decrypt("other", new byte[16]));
        });

        var entries = logger.entries();
        assertTrue(entries.stream().anyMatch(e -> e.level() == Level.DEBUG
                && e.eventId() == HkdfGuardLog.SENSITIVE_OPERATION_LOGGED && e.message().contains("item")));
        assertTrue(entries.stream().anyMatch(e -> e.level() == Level.ERROR && e.exception() instanceof HttpResponseException));
        assertTrue(entries.stream().noneMatch(e -> e.message().contains("never-logged")));
    }

    @Test
    void logOptionsTheCallerSet_AreReplaced_SoNoResponseIsLoggedWithItsBody() {
        var logged = new AtomicInteger();
        var bodyLogging = new HttpLogOptions().setLogLevel(HttpLogDetailLevel.BODY_AND_HEADERS).setResponseLogger(new CountingResponseLogger(logged));
        vault.set("item", "never-logged");

        // The control: a client of the caller's own, with these options, logs every response.
        vault.builder().httpLogOptions(bodyLogging).buildClient().getSecret("item");
        assertTrue(logged.get() > 0);

        logged.set(0);
        var cache = new AzureKeyVaultSecretCacheImpl(vault.builder().httpLogOptions(bodyLogging), ring);
        assertEquals("never-logged", decryptString(cache, "item"));
        assertEquals(0, logged.get());
    }

    @ParameterizedTest
    @CsvSource({"BODY, NONE", "BODY_AND_HEADERS, HEADERS", "HEADERS, HEADERS", "BASIC, BASIC", "NONE, NONE"})
    void withoutBodies_KeepsTheLevel_ButNeverLogsABody(HttpLogDetailLevel level, HttpLogDetailLevel expected) {
        var options = new HttpLogOptions().setLogLevel(level);

        assertEquals(expected, AzureKeyVaultSecretCacheImpl.withoutBodies(options).getLogLevel());
        assertFalse(AzureKeyVaultSecretCacheImpl.withoutBodies(options).getLogLevel().shouldLogBody());
    }

    @Test
    void aPipelineTheCallerSet_IsCleared_SoTheCapturePolicyAlwaysRuns() {
        var bypass = new HttpPipelineBuilder()
                .httpClient(request -> Mono.error(new AssertionError("The caller's pipeline was used.")))
                .build();
        var cache = new AzureKeyVaultSecretCacheImpl(vault.builder().pipeline(bypass), ring);
        vault.set("item", "value");

        assertEquals("value", decryptString(cache, "item"));
        assertTrue(vault.bodiesSeenBySecretClient.get(0).contains("\"value\":\"\""));
    }

    @Test
    void aDefaultBuilder_MakesNoCallUntilASecretIsRequested() {
        var builder = new SecretClientBuilder()
                .vaultUrl("https://example.vault.azure.net/")
                .credential(new DefaultAzureCredentialBuilder().build());
        var cache = new AzureKeyVaultSecretCacheImpl(builder, ring);

        // An invalid name never reaches the client, so this needs no network or credential.
        assertEquals(0, cache.decrypt("not:a:secret", new byte[16]));
    }

    @Test
    void theConstructor_RejectsNulls_AndABuilderWithoutAVault() {
        assertThrows(NullPointerException.class, () -> new AzureKeyVaultSecretCacheImpl(null, ring));
        assertThrows(NullPointerException.class, () -> new AzureKeyVaultSecretCacheImpl(vault.builder(), null));
        assertThrows(IllegalStateException.class, () -> new AzureKeyVaultSecretCacheImpl(
                new SecretClientBuilder().credential(SecretsHttpStub.CREDENTIAL).httpClient(vault), ring));
    }

    /** Counts every response the logging policy hands it. */
    private record CountingResponseLogger(AtomicInteger logged) implements HttpResponseLogger {
        @Override
        public Mono<HttpResponse> logResponse(ClientLogger logger, HttpResponseLoggingContext context) {
            logged.incrementAndGet();
            return Mono.just(context.getHttpResponse());
        }

        @Override
        public HttpResponse logResponseSync(ClientLogger logger, HttpResponseLoggingContext context) {
            logged.incrementAndGet();
            return context.getHttpResponse();
        }
    }
}
