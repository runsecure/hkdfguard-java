package io.github.runsecure.hkdfguard.pipeline.awssecretsmanager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.abstractions.SecretPipelineWriter;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.pipeline.contract.SecretPipelineWriterContractTest;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

/**
 * The writer's contract, and what only it does, through a real SecretsManagerAsyncClient - the
 * writer's per-request capture included - answered by {@link FakeSecretsManager} instead of the
 * network.
 */
class AwsSecretsManagerSecretPipelineWriterImplTest extends SecretPipelineWriterContractTest {
    private final FakeSecretsManager aws = new FakeSecretsManager();
    private final Unmarshalled unmarshalled = new Unmarshalled();
    private final SecretsManagerAsyncClient client = aws.client(null, unmarshalled);

    @AfterEach
    void closeClient() {
        client.close();
        aws.close();
    }

    // No key ring anywhere: the only key is the protector's.
    @Override
    protected SecretPipelineWriter createWriter(PipelineDataProtector protector, List<String> secretNames) {
        return new AwsSecretsManagerSecretPipelineWriterImpl(client, protector, secretNames);
    }

    @Override
    protected void setText(String name, String text) {
        aws.setString(name, text);
    }

    @Override
    protected void setKeys(String name, String json) {
        aws.setString(name, json);
    }

    @Override
    protected void failReads() {
        aws.failWith("AccessDeniedException", 400);
    }

    @Override
    protected Class<? extends Throwable> readFailure() {
        return SecretsManagerException.class;
    }

    @Override
    protected List<String> reads() {
        return List.copyOf(aws.gets);
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

    @Test
    void theUnmarshalledResponse_HoldsNothing_AndEveryChunkOfTheBodyIsZeroed() {
        aws.setString("item", "s3cret");
        try (var writer = createWriter("item")) {
            pull(writer);

            assertEquals(List.of(new Unmarshalled.Response(null, null, null)), List.copyOf(unmarshalled.responses));
            for (var chunk : aws.bodies.peek())
                for (var b : chunk)
                    assertEquals(0, b);
            assertTrue(aws.unexpectedOperations.isEmpty());
        }
    }

    @Test
    void theApplicationsClient_IsLeftAsItIs() {
        aws.setString("item", "s3cret");
        try (var writer = createWriter("item")) {
            pull(writer);

            var response = client.getSecretValue(r -> r.secretId("item")).join();

            assertEquals("s3cret", response.secretString());
        }
    }

    @Test
    void aNameWithoutAKey_ReadsTheWholeSecretString() {
        aws.setString("prod/app", "{\"user\":\"app\"}");
        try (var writer = createWriter("prod/app", "prod/app#user")) {
            pull(writer);

            assertEquals("{\"user\":\"app\"}", decrypt(writer.getProtectedSecrets().get("prod__app"), "prod__app"));
            assertEquals("app", decrypt(writer.getProtectedSecrets().get("prod__app__user"), "prod__app__user"));
            assertEquals(List.of("prod/app"), reads());
        }
    }

    @Test
    void anEmptySecret_IsMissing() {
        aws.setEmpty("empty");
        try (var writer = createWriter("empty")) {
            assertPullFails(NoSuchElementException.class, writer);
        }
    }

    @Test
    void aSecretBinary_IsRefused() {
        aws.setBinary("binary", new byte[] {1, 2, 3});
        try (var writer = createWriter("binary")) {
            assertPullFails(InvalidSecretDataException.class, writer);
            assertTrue(writer.getProtectedSecrets().isEmpty());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"SecretString\":\"x\" ", "[\"SecretString\"]", "", "{\"SecretString\":\"a\",\"SecretString\":\"b\"}"})
    void aResponseThatIsntSecretsManagersJson_IsRefused(String body) {
        aws.rawBody = body.getBytes(StandardCharsets.UTF_8);
        try (var writer = createWriter("item")) {
            assertPullFails(InvalidSecretDataException.class, writer);
            assertTrue(writer.getProtectedSecrets().isEmpty());
        }
    }

    // A body naming another secret, none, or more than one name: refused, and nothing it held is kept.
    @ParameterizedTest
    @ValueSource(strings = {"{\"Name\":\"other\",\"SecretString\":\"wrong\"}", "{\"Name\":\"ITEM\",\"SecretString\":\"wrong\"}",
            "{\"SecretString\":\"wrong\"}", "{\"Name\":\"item\",\"Name\":\"other\",\"SecretString\":\"wrong\"}",
            "{\"Name\":\"other\",\"Name\":\"item\",\"SecretString\":\"wrong\"}", "{\"Name\":null,\"SecretString\":\"wrong\"}"})
    void aResponseNamingAnotherSecret_IsRefused(String body) {
        aws.rawBody = body.getBytes(StandardCharsets.UTF_8);
        try (var writer = createWriter("item")) {
            assertPullFails(CryptographicException.class, writer);
            assertTrue(writer.getProtectedSecrets().isEmpty());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"ConnectionStrings:Admin", "user@example", "a+b", "a=b", ".hidden"})
    void aNameNoFileCanHave_IsRefused(String secretName) {
        assertThrows(IllegalArgumentException.class, () -> createWriter(secretName));
    }

    @Test
    void isValidSecretName_IsSecretsManagersRule() {
        assertTrue(AwsSecretsManagerSecretPipelineWriterImpl.isValidSecretName("prod/a_b+c=d.e@f-g"));
        assertTrue(AwsSecretsManagerSecretPipelineWriterImpl.isValidSecretName("a".repeat(AwsSecretsManagerSecretPipelineWriterImpl.MAX_SECRET_NAME_LENGTH)));
        assertFalse(AwsSecretsManagerSecretPipelineWriterImpl.isValidSecretName("a".repeat(AwsSecretsManagerSecretPipelineWriterImpl.MAX_SECRET_NAME_LENGTH + 1)));
        assertFalse(AwsSecretsManagerSecretPipelineWriterImpl.isValidSecretName(""));
        assertFalse(AwsSecretsManagerSecretPipelineWriterImpl.isValidSecretName(null));
        assertFalse(AwsSecretsManagerSecretPipelineWriterImpl.isValidSecretName("a:b"));
    }

    @Test
    void constructor_ChecksTheClient() {
        assertThrows(NullPointerException.class, () -> new AwsSecretsManagerSecretPipelineWriterImpl(null, protector, List.of("item")));
    }
}
