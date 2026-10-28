package io.github.runsecure.hkdfguard.cache.awssecretsmanager;

import static io.github.runsecure.hkdfguard.cache.awssecretsmanager.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.cache.awssecretsmanager.Futures.await;
import static io.github.runsecure.hkdfguard.cache.awssecretsmanager.TestRings.text;
import static io.github.runsecure.hkdfguard.cache.awssecretsmanager.TestRings.utf8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheCollectionImpl;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheImpl;
import io.github.runsecure.hkdfguard.cache.SecretJsonBody;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.event.Level;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;

/**
 * The cache through a real SecretsManagerAsyncClient - its per-request capture included - answered
 * by {@link FakeSecretsManager} instead of the network.
 */
class AwsSecretsManagerSecretCacheImplTest {
    // A key/value secret as AWS Secrets Manager's console stores one.
    private static final String KEY_VALUE_SECRET = """
            {
              "test-credential-1": "This is my first credential",
              "service-credential-3": "This is my third credential",
              "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
              "domain-credential-17": "fakedomain/thiscredential",
              "port": 5432
            }""";

    private final FakeSecretsManager aws = new FakeSecretsManager();
    private final Unmarshalled unmarshalled = new Unmarshalled();
    private final SecretsManagerAsyncClient client = aws.client(null, unmarshalled);
    private final KeyRingImpl ring = TestRings.ring();
    private final AwsSecretsManagerSecretCacheImpl cache = new AwsSecretsManagerSecretCacheImpl(client, ring, null);

    @AfterEach
    void close() {
        client.close();
        aws.close();
        ring.close();
    }

    private static String decryptString(ProtectedReadOnlyCache cache, String name) {
        var result = new char[512];
        return new String(result, 0, cache.decrypt(name, result));
    }

    /** What every GetSecretValueResponse the client's unmarshaller produced held, read as it was produced. */
    static final class Unmarshalled implements ExecutionInterceptor {
        record Response(String arn, String secretString, Integer secretBinaryLength) {
        }

        final ConcurrentLinkedQueue<Response> responses = new ConcurrentLinkedQueue<>();

        @Override
        public void afterUnmarshalling(Context.AfterUnmarshalling context, ExecutionAttributes executionAttributes) {
            if (context.response() instanceof GetSecretValueResponse response)
                responses.add(new Response(response.arn(), response.secretString(),
                        response.secretBinary() == null ? null : response.secretBinary().asByteArrayUnsafe().length));
        }
    }

    private static void eventually(BooleanSupplier condition) {
        var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline)
                throw new AssertionError("The condition never held.");
            Futures.sleep(10);
        }
    }

    @Test
    void decrypt_OnMiss_FetchesTheOneSecret_ThenServesItFromTheCache() {
        aws.setString("prod/Db-Password", "s3cret");

        assertEquals("s3cret", decryptString(cache, "prod/Db-Password"));
        var bytes = new byte[64];
        assertEquals("s3cret", text(bytes, cache.decrypt("prod/Db-Password", bytes)));

        assertEquals(List.of("prod/Db-Password"), List.copyOf(aws.gets));
        assertTrue(aws.unexpectedOperations.isEmpty());
    }

    @Test
    void theUnmarshalledResponse_HoldsTheValueBlanked() {
        aws.setString("text", "s3cret");
        aws.setBinary("binary", new byte[] {1, 2, 3});

        assertEquals("s3cret", decryptString(cache, "text"));
        assertEquals(3, cache.decrypt("binary", new byte[16]));

        assertEquals(2, unmarshalled.responses.size());
        for (var response : unmarshalled.responses) {
            assertEquals("", response.secretString() == null ? "" : response.secretString());
            assertTrue(response.secretBinaryLength() == null || response.secretBinaryLength() == 0);
            assertTrue(response.arn().startsWith("arn:aws:secretsmanager:"), response.arn());
        }
    }

    @Test
    void theCapture_IsAttachedToEachRequest_NotToTheApplicationsClient() {
        aws.setString("a", "1");
        aws.setString("b", "2");

        assertEquals("1", decryptString(cache, "a"));
        assertEquals("2", decryptString(cache, "b"));

        var interceptors = client.serviceClientConfiguration().overrideConfiguration().executionInterceptors();
        assertTrue(interceptors.contains(unmarshalled));
        assertTrue(interceptors.stream().noneMatch(SecretCapture.class::isInstance), interceptors.toString());
    }

    @Test
    void everyBufferTheHttpClientHandedOver_AndThatHeldTheSecret_IsZeroed() {
        aws.setString("text", "s3cret-value-spanning-several-chunks");
        aws.setBinary("binary", utf8("binary-value-spanning-several-chunks"));

        assertEquals("s3cret-value-spanning-several-chunks", decryptString(cache, "text"));
        assertTrue(cache.decrypt("binary", new byte[64]) > 0);

        assertEquals(2, aws.bodies.size());
        for (var chunks : aws.bodies) {
            assertTrue(chunks.size() > 1);
            for (var chunk : chunks)
                assertArrayEquals(new byte[chunk.length], chunk);
        }
    }

    @Test
    void aValueWithJsonEscapes_IsUnescapedExactly() {
        var secret = "p\"a\\ss/wörd\n\u0001秘密";
        aws.setString("escaped", secret);

        assertEquals(secret, decryptString(cache, "escaped"));
    }

    @Test
    void aBinarySecret_IsCachedAsItsBytes() {
        aws.setBinary("binary", new byte[] {0, 1, (byte) 254, (byte) 255});

        var result = new byte[16];
        var written = cache.decrypt("binary", result);

        assertArrayEquals(new byte[] {0, 1, (byte) 254, (byte) 255}, Arrays.copyOf(result, written));
    }

    @Test
    void aKeyValueSecret_IsCachedWholeAndByKey_FromOneCall_AndTheSdkNeverSeesIt() {
        aws.setString("prod/App", KEY_VALUE_SECRET);

        assertEquals("0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
                decryptString(cache, "prod/App#api-credential-21"));
        assertEquals("This is my first credential", decryptString(cache, "prod/App#test-credential-1"));
        assertEquals("This is my third credential", decryptString(cache, "prod/App#service-credential-3"));
        assertEquals("fakedomain/thiscredential", decryptString(cache, "prod/App#domain-credential-17"));
        assertEquals("5432", decryptString(cache, "prod/App#port"));
        assertEquals(KEY_VALUE_SECRET, decryptString(cache, "prod/App"));
        assertEquals(0, cache.decrypt("prod/app#port", new byte[16]));

        assertEquals(List.of("prod/App", "prod/app"), List.copyOf(aws.gets));
        assertEquals("", unmarshalled.responses.peek().secretString());
    }

    @Test
    void aBinarySecretHoldingJson_IsNotSplit() {
        aws.setBinary("binary", utf8("{\"k\":\"v\"}"));

        assertEquals("{\"k\":\"v\"}", decryptString(cache, "binary"));
        assertEquals(0, cache.decrypt("binary#k", new byte[16]));
    }

    @Test
    void decryptAsync_FetchesWithoutBlocking_AndTheSdkNeverSeesTheValue() {
        aws.setString("prod/App", KEY_VALUE_SECRET);

        var chars = new char[512];
        assertEquals("This is my first credential", new String(chars, 0, await(cache.decryptAsync("prod/App#test-credential-1", chars))));
        assertEquals(KEY_VALUE_SECRET, new String(chars, 0, await(cache.decryptAsync("prod/App", chars))));
        assertTrue(await(cache.findMaxDecryptedLengthAsync("prod/App#port")).orElseThrow() >= 4);
        assertEquals(0, await(cache.decryptAsync("missing", new byte[16])));

        assertEquals(List.of("prod/App", "missing"), List.copyOf(aws.gets));
        assertEquals("", unmarshalled.responses.peek().secretString());
    }

    @Test
    void decryptAsync_PropagatesAnAwsFailure() {
        aws.failWith("InvalidRequestException", 400);
        assertFailsWith(InvalidRequestException.class, cache.decryptAsync("item", new byte[16]));

        aws.failWith = null;
        aws.setString("item", "value");
        assertEquals(5, await(cache.decryptAsync("item", new byte[16])));
    }

    @Test
    void cancellingDecryptAsync_CancelsTheCall_AndTheNextLookupFetchesAgain() throws InterruptedException {
        aws.setString("item", "value");
        var release = new CountDownLatch(1);
        aws.onGet = () -> {
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };

        var lookup = cache.decryptAsync("item", new byte[16]);
        eventually(() -> aws.gets.size() == 1);
        assertTrue(lookup.cancel(true));

        // The SDK cancels the HTTP request it was waiting on.
        var call = aws.calls.peek();
        eventually(call::isDone);
        assertTrue(call.isCompletedExceptionally());

        aws.onGet = null;
        release.countDown();
        assertEquals(5, await(cache.decryptAsync("item", new byte[16])));
        assertEquals(2, aws.gets.size());
    }

    @Test
    void findMaxDecryptedLength_OnMiss_FetchesTheSecret() {
        aws.setString("api-key", "value");

        assertTrue(cache.findMaxDecryptedLength("api-key").orElseThrow() >= 5);
        assertEquals("value", decryptString(cache, "api-key"));
        assertEquals(1, aws.gets.size());
    }

    @Test
    void namesDifferingOnlyInCase_AreDifferentSecrets_AndDifferentEntries() {
        aws.setString("prod/Db", "upper");
        aws.setString("prod/db", "lower");

        assertEquals("upper", decryptString(cache, "prod/Db"));
        assertEquals("lower", decryptString(cache, "prod/db"));
        assertEquals(0, cache.decrypt("PROD/DB", new byte[16]));
        assertEquals("upper", decryptString(cache, "prod/Db"));

        assertEquals(List.of("prod/Db", "prod/db", "PROD/DB"), List.copyOf(aws.gets));
    }

    @Test
    void aMissingSecret_ReturnsZero_AndIsLookedUpAgainUntilItExists() {
        assertEquals(0, cache.decrypt("later", new byte[16]));
        assertTrue(cache.findMaxDecryptedLength("later").isEmpty());

        aws.setString("later", "now here");
        assertEquals("now here", decryptString(cache, "later"));
        assertEquals(3, aws.gets.size());
    }

    @Test
    void anEmptySecret_IsReportedMissing() {
        aws.setEmpty("none");
        aws.setString("empty-string", "");
        aws.setBinary("empty-binary", new byte[0]);

        assertEquals(0, cache.decrypt("none", new byte[16]));
        assertEquals(0, cache.decrypt("empty-string", new byte[16]));
        assertEquals(0, cache.decrypt("empty-binary", new byte[16]));
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"SecretString\":\"a\",\"SecretBinary\":\"Yg==\"}", "{\"SecretBinary\":\"not base64!\"}", "not json"})
    void aResponseThatCantBeTrusted_IsRefused(String body) {
        aws.rawBody = utf8(body);

        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));
        assertFailsWith(InvalidSecretDataException.class, cache.decryptAsync("item", new byte[16]));
        assertTrue(unmarshalled.responses.isEmpty());
    }

    @Test
    void aResponseBodyOverTheLimit_IsRefused_WithoutReadingItAll() {
        var body = new byte[SecretJsonBody.MAX_BODY_LENGTH + 64 * 1024];
        Arrays.fill(body, (byte) 'a');
        var prefix = utf8("{\"SecretString\":\"");
        System.arraycopy(prefix, 0, body, 0, prefix.length);
        aws.chunkLength = 64 * 1024;
        aws.rawBody = body;

        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));

        // What was read before the limit was reached is zeroed.
        var chunks = aws.bodies.peek();
        assertArrayEquals(new byte[chunks.get(0).length], chunks.get(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "ConnectionStrings:Admin", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf", "has space",
            "café", "bang!"})
    void aNameSecretsManagerCantHold_IsMissing_WithoutCallingAws(String name) {
        assertEquals(0, cache.decrypt(name, new byte[16]));
        assertEquals(0, cache.decrypt(name, new char[16]));
        assertTrue(cache.findMaxDecryptedLength(name).isEmpty());
        assertEquals(0, await(cache.decryptAsync(name, new byte[16])));
        assertTrue(aws.gets.isEmpty());
        assertTrue(aws.calls.isEmpty());
    }

    @Test
    void isValidSecretName_AcceptsTheSecretsManagerCharacterSet_UpTo512() {
        assertTrue(AwsSecretsManagerSecretCacheImpl.isValidSecretName("a"));
        assertTrue(AwsSecretsManagerSecretCacheImpl.isValidSecretName("prod/app_1+x=y.z@w-v"));
        assertTrue(AwsSecretsManagerSecretCacheImpl.isValidSecretName("x".repeat(AwsSecretsManagerSecretCacheImpl.MAX_SECRET_NAME_LENGTH)));
        assertFalse(AwsSecretsManagerSecretCacheImpl.isValidSecretName("x".repeat(AwsSecretsManagerSecretCacheImpl.MAX_SECRET_NAME_LENGTH + 1)));
        assertFalse(AwsSecretsManagerSecretCacheImpl.isValidSecretName(""));
        assertFalse(AwsSecretsManagerSecretCacheImpl.isValidSecretName(null));
    }

    @Test
    void anAwsFailure_Propagates_AndIsRetriedOnTheNextLookup() {
        aws.setString("item", "value");
        aws.failWith("InvalidRequestException", 400);

        assertThrows(InvalidRequestException.class, () -> cache.decrypt("item", new byte[16]));

        aws.failWith = null;
        assertEquals("value", decryptString(cache, "item"));
        assertEquals(2, aws.gets.size());
    }

    @Test
    void aCredentialFailure_Propagates() {
        try (var failing = aws.client(() -> {
            throw SdkClientException.create("Unable to load credentials.");
        })) {
            var cache = new AwsSecretsManagerSecretCacheImpl(failing, ring, null);

            assertThrows(SdkClientException.class, () -> cache.decrypt("item", new char[16]));
            assertFailsWith(SdkClientException.class, cache.decryptAsync("item", new char[16]));
            assertTrue(aws.gets.isEmpty());
        }
    }

    @Test
    void concurrentMissesOnOneName_ShareOneFetch() throws InterruptedException {
        aws.setString("shared", "value");
        var release = new CountDownLatch(1);
        aws.onGet = () -> {
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };

        var lookups = new ArrayList<CompletableFuture<String>>();
        for (var i = 0; i < 8; i++)
            lookups.add(CompletableFuture.supplyAsync(() -> decryptString(cache, "shared")));
        lookups.add(cache.decryptAsync("shared", new char[16]).thenApply(n -> "value".substring(0, n)));
        Futures.sleep(200);
        release.countDown();

        for (var lookup : lookups)
            assertEquals("value", await(lookup));
        assertEquals(1, aws.gets.size());
    }

    @Test
    void aLargeSecret_RoundTrips() {
        var large = "é-秘密-".repeat(3000);
        assertTrue(large.getBytes(StandardCharsets.UTF_8).length > 16 * 1024);
        aws.setString("large", large);

        var max = cache.findMaxDecryptedLength("large").orElseThrow();
        var result = new char[max];
        assertEquals(large, new String(result, 0, cache.decrypt("large", result)));
    }

    @Test
    void aCachedSecret_StillDecryptsAfterTheRingRotates() {
        aws.setString("before", "v1 value");
        aws.setString("after", "v2 value");

        assertEquals("v1 value", decryptString(cache, "before"));
        ring.add(2, TestRings.newKey());

        assertEquals("v2 value", decryptString(cache, "after"));
        assertEquals("v1 value", decryptString(cache, "before"));
    }

    @Test
    void inACollection_OnlyNamesTheEarlierSourcesMiss_ReachAws() {
        aws.setString("from-aws", "aws value");
        var local = new ProtectedCacheImpl(ring);
        local.add("ConnectionStrings:Admin", "local value".toCharArray());
        var collection = new ProtectedCacheCollectionImpl().add(local).add(cache);

        assertEquals("local value", decryptString(collection, "ConnectionStrings:Admin"));
        assertEquals("aws value", decryptString(collection, "from-aws"));
        assertEquals(List.of("from-aws"), List.copyOf(aws.gets));
    }

    @Test
    void withSensitiveLogging_AFetchLogsTheNameOnly_AndAFailureLogsAnError() {
        var logger = new RecordingLogger();
        var cache = new AwsSecretsManagerSecretCacheImpl(client, ring, logger);
        aws.setString("prod/Item", "never-logged");

        TestRings.withSensitiveLogging(() -> {
            assertEquals("never-logged", decryptString(cache, "prod/Item"));
            aws.failWith("InternalServiceError", 500);
            assertThrows(InternalServiceErrorException.class, () -> cache.decrypt("other", new byte[16]));
        });

        // The secret's own name, not its escaped entry name.
        var entries = logger.entries();
        assertTrue(entries.stream().anyMatch(e -> e.level() == Level.DEBUG
                && e.eventId() == HkdfGuardLog.SENSITIVE_OPERATION_LOGGED && e.message().contains("prod/Item")));
        assertTrue(entries.stream().anyMatch(e -> e.level() == Level.ERROR && e.exception() instanceof InternalServiceErrorException));
        assertTrue(entries.stream().noneMatch(e -> e.message().contains("never-logged")));
    }

    @Test
    void theConstructor_RejectsANullClientOrRing_AndAcceptsANullLogger() {
        assertThrows(NullPointerException.class, () -> new AwsSecretsManagerSecretCacheImpl(null, ring, null));
        assertThrows(NullPointerException.class, () -> new AwsSecretsManagerSecretCacheImpl(client, null, null));
        assertEquals(0, new AwsSecretsManagerSecretCacheImpl(client, ring, null).decrypt("missing", new byte[16]));
    }
}
