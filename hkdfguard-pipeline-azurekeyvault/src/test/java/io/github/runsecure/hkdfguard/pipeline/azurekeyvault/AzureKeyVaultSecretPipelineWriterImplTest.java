package io.github.runsecure.hkdfguard.pipeline.azurekeyvault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpPipeline;
import com.azure.core.http.HttpPipelineBuilder;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.policy.HttpLogDetailLevel;
import com.azure.core.http.policy.HttpLogOptions;
import com.azure.core.util.Context;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.abstractions.SecretPipelineWriter;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.pipeline.contract.SecretPipelineWriterContractTest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** The writer's contract, and what only it does, with a real SecretClient and its own pipeline policy over a stub Key Vault. */
class AzureKeyVaultSecretPipelineWriterImplTest extends SecretPipelineWriterContractTest {
    private final SecretsHttpStub vault = new SecretsHttpStub();

    // No key ring anywhere: the only key is the protector's.
    @Override
    protected SecretPipelineWriter createWriter(PipelineDataProtector protector, List<String> secretNames) {
        return new AzureKeyVaultSecretPipelineWriterImpl(vault.builder(), protector, secretNames);
    }

    @Override
    protected void setText(String name, String text) {
        vault.set(name, text);
    }

    @Override
    protected void setKeys(String name, String json) {
        vault.set(name, json);
    }

    @Override
    protected void failReads() {
        vault.failWith = 403;
    }

    @Override
    protected Class<? extends Throwable> readFailure() {
        return HttpResponseException.class;
    }

    @Override
    protected List<String> reads() {
        return List.copyOf(vault.gets);
    }

    // The stub's own token, so the request needs no authentication policy.
    private static HttpRequest getSecret(String name) {
        return new HttpRequest(HttpMethod.GET, SecretsHttpStub.VAULT + "/secrets/" + name + "/")
                .setHeader(HttpHeaderName.AUTHORIZATION, "Bearer " + SecretsHttpStub.TOKEN);
    }

    private HttpPipeline pipeline() {
        return new HttpPipelineBuilder().policies(PipelineSecretCapturePolicy.INSTANCE).httpClient(vault).build();
    }

    @Test
    void secretClient_SeesOnlyAnEmptyObject_AndTheBodyIsNeverBuffered() {
        vault.set("Item", "s3cret");
        try (var writer = createWriter("Item")) {
            pull(writer);

            assertEquals("s3cret", decrypt(writer.getProtectedSecrets().get("Item"), "Item"));
            assertEquals(List.of("{}"), vault.bodiesSeenBySecretClient);
            assertEquals(List.of(false), vault.eagerReads);
            assertTrue(vault.unexpectedRequests.isEmpty());
        }
    }

    @Test
    void anotherClientFromTheSameBuilder_ReadsSecretsAsUsual() {
        vault.set("Item", "s3cret");
        var builder = vault.builder();
        try (var writer = new AzureKeyVaultSecretPipelineWriterImpl(builder, protector, List.of("Item"))) {
            var other = builder.buildClient();

            assertEquals("s3cret", other.getSecret("Item").getValue());
            assertEquals("s3cret", builder.buildAsyncClient().getSecret("Item").block().getValue());
        }
    }

    @Test
    void aNameWithoutAKey_ReadsTheWholeValue() {
        vault.set("Db-Login", "{\"user\":\"app\"}");
        try (var writer = createWriter("Db-Login", "Db-Login#user")) {
            pull(writer);

            assertEquals("{\"user\":\"app\"}", decrypt(writer.getProtectedSecrets().get("Db-Login"), "Db-Login"));
            assertEquals("app", decrypt(writer.getProtectedSecrets().get("Db-Login__user"), "Db-Login__user"));
            assertEquals(List.of("Db-Login"), reads());
        }
    }

    @Test
    void aBodyTheHttpClientBuffered_IsZeroed() {
        vault.set("Item", "s3cret");
        vault.alwaysBuffer = true;
        try (var writer = createWriter("Item")) {
            pull(writer);

            assertEquals("s3cret", decrypt(writer.getProtectedSecrets().get("Item"), "Item"));
            var buffered = vault.bufferedBodies.get(0);
            assertArrayEquals(new byte[buffered.length], buffered);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"value\":\"x\" ", "[\"value\"]", "", "{\"value\":\"a\",\"value\":\"b\"}"})
    void aResponseThatIsntKeyVaultsJson_IsRefused(String body) {
        vault.rawBody = body;
        try (var writer = createWriter("Item")) {
            assertPullFails(InvalidSecretDataException.class, writer);
            assertTrue(writer.getProtectedSecrets().isEmpty());
        }
    }

    @Test
    void aResponseWithoutAStringValue_HoldsNothing() {
        vault.rawBody = "{\"value\":5,\"id\":\"x\"}";
        try (var writer = createWriter("Item")) {
            assertPullFails(NoSuchElementException.class, writer);
        }
    }

    @Test
    void theAsyncPipeline_CapturesTheBody_AndHandsOnAnEmptyObject() {
        var pipeline = pipeline();
        vault.set("Db-Password", "s3cret");
        var captured = new ArrayList<String>();
        var capture = new PipelineSecretCapturePolicy.Capture((body, length) -> captured.add(new String(body, 0, length, StandardCharsets.UTF_8)));

        try (var response = pipeline.send(getSecret("Db-Password"), PipelineSecretCapturePolicy.context(capture)).block()) {
            assertEquals("{}", response.getBodyAsString().block());
            assertEquals("2", response.getHeaders().getValue(HttpHeaderName.CONTENT_LENGTH));
        }

        assertTrue(capture.captured());
        assertEquals(1, captured.size());
        assertTrue(captured.get(0).contains("\"value\":\"s3cret\""));
        assertEquals(List.of(false), vault.eagerReads);
    }

    @Test
    void theAsyncPipeline_ZeroesABodyTheHttpClientBuffered() {
        var pipeline = pipeline();
        vault.set("Db-Password", "s3cret");
        vault.alwaysBuffer = true;
        var capture = new PipelineSecretCapturePolicy.Capture((body, length) -> { });

        pipeline.send(getSecret("Db-Password"), PipelineSecretCapturePolicy.context(capture)).block().close();

        var buffered = vault.bufferedBodies.get(0);
        assertArrayEquals(new byte[buffered.length], buffered);
    }

    @Test
    void anErrorResponse_IsLeftForTheClient_Buffered() {
        var pipeline = pipeline();
        var capture = new PipelineSecretCapturePolicy.Capture((body, length) -> {
            throw new AssertionError("An error response holds no secret.");
        });

        try (var response = pipeline.send(getSecret("missing"), PipelineSecretCapturePolicy.context(capture)).block()) {
            assertEquals(404, response.getStatusCode());
            assertTrue(response.getBodyAsBinaryData().toString().contains("SecretNotFound"));
        }
        try (var response = pipeline.sendSync(getSecret("missing"), PipelineSecretCapturePolicy.context(capture))) {
            assertEquals(404, response.getStatusCode());
        }
        assertFalse(capture.captured());
    }

    @Test
    void aCaptureThatRefusesTheBody_FailsTheRequest() {
        var pipeline = pipeline();
        vault.set("Item", "s3cret");
        var refusal = new InvalidSecretDataException("refused");
        var capture = new PipelineSecretCapturePolicy.Capture((body, length) -> {
            throw refusal;
        });

        var e = assertThrows(InvalidSecretDataException.class, () -> pipeline.sendSync(getSecret("Item"), PipelineSecretCapturePolicy.context(capture)));
        assertEquals(refusal, e);
    }

    @Test
    void aRequestWithoutACapture_PassesThroughUntouched() {
        var pipeline = pipeline();
        vault.set("item", "value");

        try (var response = pipeline.send(getSecret("item")).block()) {
            assertInstanceOf(SecretsHttpStub.StubResponse.class, response);
            assertTrue(response.getBodyAsString().block().contains("\"value\":\"value\""));
        }
        try (var response = pipeline.sendSync(getSecret("item"), Context.NONE)) {
            assertInstanceOf(SecretsHttpStub.StubResponse.class, response);
        }
    }

    @ParameterizedTest
    @CsvSource({"BODY, NONE", "BODY_AND_HEADERS, HEADERS", "HEADERS, HEADERS", "BASIC, BASIC", "NONE, NONE"})
    void theLogOptions_NeverLogABody(HttpLogDetailLevel given, HttpLogDetailLevel used) {
        assertEquals(used, AzureKeyVaultSecretPipelineWriterImpl.withoutBodies(new HttpLogOptions().setLogLevel(given)).getLogLevel());
    }

    @ParameterizedTest
    @ValueSource(strings = {"Db_Password", "prod/app"})
    void aNameKeyVaultCantHold_IsRefused(String secretName) {
        assertThrows(IllegalArgumentException.class, () -> createWriter(secretName));
    }

    @Test
    void isValidSecretName_IsKeyVaultsRule() {
        assertTrue(AzureKeyVaultSecretPipelineWriterImpl.isValidSecretName("Db-Login-2"));
        assertTrue(AzureKeyVaultSecretPipelineWriterImpl.isValidSecretName("a".repeat(AzureKeyVaultSecretPipelineWriterImpl.MAX_SECRET_NAME_LENGTH)));
        assertFalse(AzureKeyVaultSecretPipelineWriterImpl.isValidSecretName("a".repeat(AzureKeyVaultSecretPipelineWriterImpl.MAX_SECRET_NAME_LENGTH + 1)));
        assertFalse(AzureKeyVaultSecretPipelineWriterImpl.isValidSecretName(""));
        assertFalse(AzureKeyVaultSecretPipelineWriterImpl.isValidSecretName(null));
    }

    @Test
    void constructor_ChecksTheBuilder() {
        assertThrows(NullPointerException.class, () -> new AzureKeyVaultSecretPipelineWriterImpl(null, protector, List.of("Item")));
    }
}
