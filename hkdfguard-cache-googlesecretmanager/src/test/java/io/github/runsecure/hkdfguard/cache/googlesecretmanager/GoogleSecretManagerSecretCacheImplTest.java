package io.github.runsecure.hkdfguard.cache.googlesecretmanager;

import static io.github.runsecure.hkdfguard.cache.googlesecretmanager.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.cache.googlesecretmanager.Futures.await;
import static io.github.runsecure.hkdfguard.cache.googlesecretmanager.TestRings.text;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.api.gax.rpc.PermissionDeniedException;
import com.google.api.gax.rpc.StatusCode;
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretManagerServiceSettings;
import com.google.cloud.secretmanager.v1.SecretPayload;
import com.google.protobuf.ByteString;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheCollectionImpl;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.event.Level;

/**
 * GoogleSecretManagerSecretCacheImpl against an in-process fake Secret Manager, through a real
 * SecretManagerServiceClient whose channel carries the ReceiveBufferScrubber.
 */
class GoogleSecretManagerSecretCacheImplTest {
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
    private final FakeSecretManager google = new FakeSecretManager();

    @AfterEach
    void close() throws InterruptedException {
        google.close();
        ring.close();
    }

    private GoogleSecretManagerSecretCacheImpl create() {
        return new GoogleSecretManagerSecretCacheImpl(google.client(), FakeSecretManager.PROJECT_ID, ring, null);
    }

    private static String decryptString(ProtectedReadOnlyCache cache, String name) {
        var result = new char[512];
        return new String(result, 0, cache.decrypt(name, result));
    }

    private static void assertZeroed(byte[] bytes) {
        for (var b : bytes)
            assertEquals(0, b);
    }

    // The payload the client parsed, and the buffer it was parsed from, both zeroed.
    private void assertTheOneResponseWasZeroed() {
        assertEquals(1, google.responses.size());
        assertZeroed(google.responses.get(0).getPayload().getData().toByteArray());
        assertEquals(1, google.receiveBuffers.size());
        assertZeroed(google.receiveBuffers.get(0));
    }

    @Test
    void decrypt_OnMiss_FetchesTheOneSecretsLatestVersion_ThenServesItFromTheCache() {
        var cache = create();
        google.set("Db-Password", "s3cret");

        assertEquals("s3cret", decryptString(cache, "Db-Password"));
        var bytes = new byte[64];
        assertEquals("s3cret", text(bytes, cache.decrypt("Db-Password", bytes)));

        assertEquals(List.of("projects/hkdfguard-test/secrets/Db-Password/versions/latest"), google.accesses);
    }

    @Test
    void theParsedPayload_AndTheReceiveBuffer_AreZeroedOnceEncrypted() {
        var cache = create();
        google.set("item", "value");

        assertEquals("value", decryptString(cache, "item"));

        assertTheOneResponseWasZeroed();
        assertTrue(google.unexpectedCalls.isEmpty());
    }

    @Test
    void aJsonPayload_IsCachedWholeAndByKey_FromOneCall_AndIsZeroed() {
        var cache = create();
        google.set("App-Credentials", KEY_VALUE_SECRET);

        assertEquals("0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
                decryptString(cache, "App-Credentials#api-credential-21"));
        assertEquals("This is my third credential", decryptString(cache, "App-Credentials#service-credential-3"));
        assertEquals("5432", decryptString(cache, "App-Credentials#port"));
        assertEquals(KEY_VALUE_SECRET, decryptString(cache, "App-Credentials"));

        assertEquals(List.of("App-Credentials"), google.gets());
        assertTheOneResponseWasZeroed();
    }

    @Test
    void decryptAsync_FetchesThroughTheClientsAsynchronousCall_AndZeroesThePayloadAndReceiveBuffer() {
        var cache = create();
        google.set("App-Credentials", KEY_VALUE_SECRET);

        var chars = new char[512];
        assertEquals("This is my third credential",
                new String(chars, 0, await(cache.decryptAsync("App-Credentials#service-credential-3", chars))));
        assertEquals(KEY_VALUE_SECRET, new String(chars, 0, await(cache.decryptAsync("App-Credentials", chars))));
        assertEquals(0, await(cache.decryptAsync("Missing", new byte[16])));

        // RemoteSecretCache's default fetchAsync would have called on a virtual thread.
        assertEquals(List.of(false, false), google.accessedOnVirtualThread);
        assertTheOneResponseWasZeroed();
        assertTrue(google.unexpectedCalls.isEmpty());
    }

    @Test
    void decryptAsync_PropagatesAGoogleFailure() {
        var cache = create();
        google.set("item", "value");
        google.failure = FakeSecretManager.error(Status.Code.PERMISSION_DENIED, "Denied in a test.");

        var e = assertFailsWith(PermissionDeniedException.class, cache.decryptAsync("item", new byte[16]));
        assertEquals(StatusCode.Code.PERMISSION_DENIED, e.getStatusCode().getCode());
    }

    @Test
    void decryptAsync_RefusesAPayloadThatDoesNotMatchItsChecksum_AndZeroesIt() {
        var cache = create();
        google.set("item", "value");
        google.tamper = r -> r.toBuilder().setPayload(r.getPayload().toBuilder().setDataCrc32C(r.getPayload().getDataCrc32C() ^ 1)).build();

        assertFailsWith(CryptographicException.class, cache.decryptAsync("item", new byte[16]));
        assertTheOneResponseWasZeroed();
    }

    @Test
    void cancellingTheLookupThatStartedAFetch_CancelsTheCall_AndALaterLookupFetchesAgain() throws InterruptedException {
        var cache = create();
        google.set("item", "value");
        google.hang = true;

        var lookup = cache.decryptAsync("item", new byte[16]);
        assertTrue(google.received.await(10, TimeUnit.SECONDS));
        assertTrue(lookup.cancel(true));

        assertTrue(google.cancelled.await(10, TimeUnit.SECONDS), "The Secret Manager call was not cancelled.");
        assertThrows(CancellationException.class, lookup::join);

        google.hang = false;
        assertEquals("value", decryptString(cache, "item"));
        assertEquals(2, google.accesses.size());
    }

    @Test
    void findMaxDecryptedLength_OnMiss_FetchesTheSecret() {
        var cache = create();
        google.set("api-key", "value");

        assertTrue(cache.findMaxDecryptedLength("api-key").orElseThrow() >= 5);
        assertEquals("value", decryptString(cache, "api-key"));
        assertEquals(1, google.accesses.size());
    }

    @Test
    void findMaxDecryptedLengthAsync_OnMiss_FetchesTheSecret() {
        var cache = create();
        google.set("api-key", "value");

        assertTrue(await(cache.findMaxDecryptedLengthAsync("api-key")).orElseThrow() >= 5);
        assertTrue(await(cache.findMaxDecryptedLengthAsync("absent")).isEmpty());
        assertEquals(2, google.accesses.size());
    }

    @Test
    void namesDifferingOnlyInCase_AreDifferentSecrets_AndDifferentEntries() {
        var cache = create();
        google.set("Db", "upper");
        google.set("db", "lower");

        assertEquals("upper", decryptString(cache, "Db"));
        assertEquals("lower", decryptString(cache, "db"));
        assertEquals(0, cache.decrypt("DB", new byte[16]));
        assertEquals("upper", decryptString(cache, "Db"));

        assertEquals(List.of("Db", "db", "DB"), google.gets());
    }

    @Test
    void aMissingSecret_ReturnsZero_AndIsLookedUpAgainUntilItExists() {
        var cache = create();

        assertEquals(0, cache.decrypt("later", new byte[16]));
        assertTrue(cache.findMaxDecryptedLength("later").isEmpty());

        google.set("later", "now here");
        assertEquals("now here", decryptString(cache, "later"));
        assertEquals(3, google.accesses.size());
    }

    @Test
    void anEmptyOrAbsentPayload_IsReportedMissing() {
        var cache = create();
        google.set("empty", new byte[0]);

        assertEquals(0, cache.decrypt("empty", new byte[16]));

        google.tamper = r -> r.toBuilder().clearPayload().build();
        google.set("no-payload", "value");
        assertEquals(0, cache.decrypt("no-payload", new byte[16]));
    }

    @Test
    void aBinarySecret_IsCachedAsItsBytes() {
        var cache = create();
        google.set("binary", new byte[] {0, 1, (byte) 254, (byte) 255});

        var result = new byte[16];
        var written = cache.decrypt("binary", result);

        assertArrayEquals(new byte[] {0, 1, (byte) 254, (byte) 255}, Arrays.copyOf(result, written));
    }

    @Test
    void aPayloadWithoutAChecksum_IsAccepted() {
        var cache = create();
        google.set("item", "value");
        google.tamper = r -> r.toBuilder().setPayload(r.getPayload().toBuilder().clearDataCrc32C()).build();

        assertEquals("value", decryptString(cache, "item"));
    }

    @Test
    void aPayloadThatDoesNotMatchItsChecksum_IsRefused_AndZeroed() {
        var cache = create();
        google.set("item", "value");
        google.tamper = r -> r.toBuilder().setPayload(r.getPayload().toBuilder().setDataCrc32C(r.getPayload().getDataCrc32C() ^ 1)).build();

        var e = assertThrows(CryptographicException.class, () -> cache.decrypt("item", new byte[16]));
        assertFalse(e.getMessage().contains("value"));
        assertTheOneResponseWasZeroed();
    }

    @ParameterizedTest
    @ValueSource(strings = {"projects/123456789012/secrets/other/versions/1", "not a resource name", ""})
    void aResponseForAnotherSecret_IsRefused_AndZeroed(String reportedName) {
        var cache = create();
        google.set("item", "value");
        google.tamper = r -> r.toBuilder().setName(reportedName).build();

        assertThrows(CryptographicException.class, () -> cache.decrypt("item", new byte[16]));
        assertTheOneResponseWasZeroed();
    }

    @Test
    void aResponseFromALocationalSecretOfTheSameName_IsAccepted() {
        var cache = create();
        google.set("item", "value");
        google.tamper = r -> r.toBuilder().setName("projects/123456789012/locations/us-east1/secrets/item/versions/3").build();

        assertEquals("value", decryptString(cache, "item"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "ConnectionStrings:Admin", "prod/db", "db.password", "has space", "café", "bang!"})
    void aNameSecretManagerCantHold_IsMissing_WithoutCallingGoogle(String name) {
        var cache = create();

        assertEquals(0, cache.decrypt(name, new byte[16]));
        assertEquals(0, cache.decrypt(name, new char[16]));
        assertTrue(cache.findMaxDecryptedLength(name).isEmpty());
        assertEquals(0, await(cache.decryptAsync(name, new byte[16])));
        assertTrue(google.accesses.isEmpty());
    }

    @Test
    void isValidSecretName_AcceptsLettersDigitsHyphensAndUnderscores_UpTo255() {
        assertTrue(GoogleSecretManagerSecretCacheImpl.isValidSecretName("a"));
        assertTrue(GoogleSecretManagerSecretCacheImpl.isValidSecretName("Db_Password-2"));
        assertTrue(GoogleSecretManagerSecretCacheImpl.isValidSecretName("x".repeat(GoogleSecretManagerSecretCacheImpl.MAX_SECRET_NAME_LENGTH)));
        assertFalse(GoogleSecretManagerSecretCacheImpl.isValidSecretName("x".repeat(GoogleSecretManagerSecretCacheImpl.MAX_SECRET_NAME_LENGTH + 1)));
        assertFalse(GoogleSecretManagerSecretCacheImpl.isValidSecretName(null));
        assertFalse(GoogleSecretManagerSecretCacheImpl.isValidSecretName(""));
    }

    @Test
    void aTooLongName_IsNeverSent() {
        var cache = create();

        assertEquals(0, cache.decrypt("x".repeat(GoogleSecretManagerSecretCacheImpl.MAX_SECRET_NAME_LENGTH + 1), new byte[16]));
        assertTrue(google.accesses.isEmpty());
    }

    // Codes the client doesn't retry: FAILED_PRECONDITION is a disabled or destroyed latest version.
    @ParameterizedTest
    @EnumSource(value = Status.Code.class, names = {"PERMISSION_DENIED", "FAILED_PRECONDITION", "INTERNAL", "UNAUTHENTICATED"})
    void aGoogleFailure_Propagates_AndIsRetriedOnTheNextLookup(Status.Code status) {
        var cache = create();
        google.set("item", "value");
        google.failure = FakeSecretManager.error(status, "refused");

        var thrown = assertThrows(ApiException.class, () -> cache.decrypt("item", new byte[16]));
        assertEquals(status.name(), thrown.getStatusCode().getCode().name());

        google.failure = null;
        assertEquals("value", decryptString(cache, "item"));
        assertEquals(2, google.accesses.size());
    }

    @Test
    void concurrentMissesOnOneName_ShareOneFetch() throws Exception {
        var cache = create();
        google.set("shared", "value");
        var release = new CountDownLatch(1);
        google.onGet = () -> {
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };

        try (var executor = Executors.newFixedThreadPool(8)) {
            var lookups = new ArrayList<CompletableFuture<String>>();
            for (var i = 0; i < 8; i++)
                lookups.add(CompletableFuture.supplyAsync(() -> decryptString(cache, "shared"), executor));
            Futures.sleep(200);
            release.countDown();

            for (var lookup : lookups)
                assertEquals("value", await(lookup));
        }
        assertEquals(1, google.accesses.size());
    }

    @Test
    void aLargeSecret_RoundTrips() {
        var cache = create();
        var large = "é-秘密-".repeat(1500);
        assertTrue(large.getBytes(StandardCharsets.UTF_8).length > 4096);
        google.set("large", large);

        var result = new char[cache.findMaxDecryptedLength("large").orElseThrow()];
        assertEquals(large, new String(result, 0, cache.decrypt("large", result)));
        assertTheOneResponseWasZeroed();
    }

    @Test
    void aCachedSecret_StillDecryptsAfterTheRingRotates() {
        var cache = create();
        google.set("before", "v1 value");
        google.set("after", "v2 value");

        assertEquals("v1 value", decryptString(cache, "before"));
        ring.add(2, TestRings.newKey());

        assertEquals("v2 value", decryptString(cache, "after"));
        assertEquals("v1 value", decryptString(cache, "before"));
    }

    @Test
    void inACollection_OnlyNamesTheEarlierSourcesMiss_ReachGoogle() {
        var googleCache = create();
        google.set("from-google", "google value");
        var local = new ProtectedCacheImpl(ring);
        local.add("ConnectionStrings:Admin", "local value".toCharArray());
        var collection = new ProtectedCacheCollectionImpl().add(local).add(googleCache);

        assertEquals("local value", decryptString(collection, "ConnectionStrings:Admin"));
        assertEquals("google value", decryptString(collection, "from-google"));
        assertEquals(List.of("from-google"), google.gets());
    }

    @Test
    void withSensitiveLogging_AFetchLogsTheNameOnly_AndAFailureLogsAnError() {
        google.set("Item", "never-logged");
        var logger = new RecordingLogger();
        var cache = new GoogleSecretManagerSecretCacheImpl(google.client(), FakeSecretManager.PROJECT_ID, ring, logger);

        TestRings.withSensitiveLogging(() -> {
            assertEquals("never-logged", decryptString(cache, "Item"));
            google.failure = FakeSecretManager.error(Status.Code.INTERNAL, "boom");
            assertThrows(ApiException.class, () -> cache.decrypt("other", new byte[16]));
        });

        // The secret's own name, not its escaped entry name.
        var entries = logger.entries();
        assertTrue(entries.stream().anyMatch(e -> e.level() == Level.DEBUG && e.message().contains("Item")));
        assertTrue(entries.stream().anyMatch(e -> e.level() == Level.ERROR && e.exception() instanceof ApiException));
        assertTrue(entries.stream().noneMatch(e -> e.message().contains("never-logged")));
    }

    @Test
    void close_LeavesACallersOwnClientOpen() {
        google.set("item", "value");
        create().close();

        assertEquals("value", decryptString(create(), "item"));
    }

    @Test
    void theConstructor_RejectsNullsAndProjectIdsThatCouldChangeTheResourcePath() {
        var client = google.client();

        assertThrows(NullPointerException.class,
                () -> new GoogleSecretManagerSecretCacheImpl((SecretManagerServiceClient) null, "p", ring, null));
        assertThrows(NullPointerException.class, () -> new GoogleSecretManagerSecretCacheImpl(client, null, ring, null));
        assertThrows(NullPointerException.class, () -> new GoogleSecretManagerSecretCacheImpl(client, "p", null, null));
        assertThrows(IllegalArgumentException.class, () -> new GoogleSecretManagerSecretCacheImpl(client, "", ring, null));
        assertThrows(IllegalArgumentException.class, () -> new GoogleSecretManagerSecretCacheImpl(client, "p/secrets/other", ring, null));
        assertThrows(IllegalArgumentException.class, () -> new GoogleSecretManagerSecretCacheImpl(client, "my project", ring, null));
        assertThrows(IllegalArgumentException.class, () -> new GoogleSecretManagerSecretCacheImpl(client, "projé", ring, null));

        // A project number, and a legacy domain-scoped ID, are both fine.
        new GoogleSecretManagerSecretCacheImpl(client, "123456789012", ring, null);
        new GoogleSecretManagerSecretCacheImpl(client, "example.com:my-project", ring, null);
    }

    @Test
    void create_AndTheSettingsConstructor_RejectAnInvalidProject_BeforeCreatingAClient() {
        // No credentials are looked up: the project is checked first.
        assertThrows(IllegalArgumentException.class, () -> GoogleSecretManagerSecretCacheImpl.create("p/x", ring, null));
        assertThrows(NullPointerException.class, () -> GoogleSecretManagerSecretCacheImpl.create("p", null, null));
        assertThrows(NullPointerException.class,
                () -> new GoogleSecretManagerSecretCacheImpl((SecretManagerServiceSettings) null, "p", ring, null));
    }

    @Test
    void theSettingsConstructor_RefusesATransportItCantAddTheScrubberTo() throws IOException {
        var channel = InProcessChannelBuilder.forName("unused").build();
        try {
            var fixed = SecretManagerServiceSettings.newBuilder()
                    .setTransportChannelProvider(FixedTransportChannelProvider.create(GrpcTransportChannel.create(channel)))
                    .setCredentialsProvider(NoCredentialsProvider.create())
                    .build();
            assertThrows(IllegalArgumentException.class,
                    () -> new GoogleSecretManagerSecretCacheImpl(fixed, FakeSecretManager.PROJECT_ID, ring, null));
        } finally {
            channel.shutdownNow();
        }

        var httpJson = SecretManagerServiceSettings.newHttpJsonBuilder().setCredentialsProvider(NoCredentialsProvider.create()).build();
        assertThrows(IllegalArgumentException.class,
                () -> new GoogleSecretManagerSecretCacheImpl(httpJson, FakeSecretManager.PROJECT_ID, ring, null));
    }

    @Test
    void theSettingsConstructor_MakesItsOwnClient_WithoutCallingGoogleUntilASecretIsRequested() throws IOException {
        var settings = SecretManagerServiceSettings.newBuilder().setCredentialsProvider(NoCredentialsProvider.create()).build();

        try (var cache = new GoogleSecretManagerSecretCacheImpl(settings, FakeSecretManager.PROJECT_ID, ring, null)) {
            // An invalid name never reaches the channel, so this needs no network.
            assertEquals(0, cache.decrypt("not:a:secret", new byte[16]));
        }
    }

    // Over gRPC's real (Netty) transport on a loopback port: the scrubber is added to the channel the
    // settings' provider builds, outside the interceptors its interceptor provider supplies, and after
    // the channel configurator already set (plaintext here: without it the call would fail).
    @Test
    void theSettingsConstructor_AddsTheScrubber_KeepingTheInterceptorProviderAndChannelConfigurator() throws Exception {
        google.set("item", "value");
        var server = google.serveOnLoopback();
        var configured = new AtomicInteger();
        try {
            var provider = SecretManagerServiceSettings.defaultGrpcTransportProviderBuilder()
                    .setEndpoint("127.0.0.1:" + server.getPort())
                    .setChannelConfigurator(builder -> {
                        configured.incrementAndGet();
                        return builder.usePlaintext();
                    })
                    .setInterceptorProvider(() -> List.of(google.receiveRecorder()))
                    .build();
            var settings = SecretManagerServiceSettings.newBuilder()
                    .setTransportChannelProvider(provider)
                    .setCredentialsProvider(NoCredentialsProvider.create())
                    .build();

            try (var cache = new GoogleSecretManagerSecretCacheImpl(settings, FakeSecretManager.PROJECT_ID, ring, null)) {
                assertEquals("value", decryptString(cache, "item"));
                assertEquals(0, await(cache.decryptAsync("absent", new byte[16])));
            }

            assertTrue(configured.get() > 0);
            // The recorder inside the scrubber saw the buffer the scrubber read each response into:
            // one, exactly the message's length, zeroed.
            assertEquals(1, google.receiveBuffers.size());
            assertEquals(AccessSecretVersionResponse.newBuilder()
                    .setName("projects/123456789012/secrets/item/versions/1")
                    .setPayload(SecretPayload.newBuilder()
                            .setData(ByteString.copyFromUtf8("value"))
                            .setDataCrc32C(FakeSecretManager.crc32c("value".getBytes(StandardCharsets.UTF_8))))
                    .build().getSerializedSize(), google.receiveBuffers.get(0).length);
            assertZeroed(google.receiveBuffers.get(0));
        } finally {
            server.shutdownNow();
            server.awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void crc32c_MatchesTheCastagnoliCheckValue() {
        assertEquals(0xE3069283L, GoogleSecretManagerSecretCacheImpl.crc32c(ByteString.copyFromUtf8("123456789")));
    }
}
