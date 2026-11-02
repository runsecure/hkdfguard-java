package io.github.runsecure.hkdfguard.cache.azurekeyvault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpPipeline;
import com.azure.core.http.HttpPipelineBuilder;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.core.util.Context;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The capture policy on its own: what SecretClient is handed, and the asynchronous pipeline, which
 * the cache's synchronous client never takes but another client sharing its builder can.
 */
class SecretCapturePolicyTest {
    private final KeyRingImpl ring = TestRings.ring();
    private final SecretsHttpStub vault = new SecretsHttpStub();

    @AfterEach
    void closeRing() {
        ring.close();
    }

    private static String decryptString(SinkProbeCache cache, String name) {
        var result = new char[64];
        return new String(result, 0, cache.decrypt(name, result));
    }

    // The stub's own token, so the request needs no authentication policy.
    private static HttpRequest getSecret(String name) {
        return new HttpRequest(HttpMethod.GET, SecretsHttpStub.VAULT + "/secrets/" + name + "/")
                .setHeader(HttpHeaderName.AUTHORIZATION, "Bearer " + SecretsHttpStub.TOKEN);
    }

    private HttpPipeline pipeline() {
        return new HttpPipelineBuilder().policies(SecretCapturePolicy.INSTANCE).httpClient(vault).build();
    }

    @Test
    void theKeyVaultSecretSecretClientReturns_HoldsAnEmptyValue() {
        var client = vault.builder().addPolicy(SecretCapturePolicy.INSTANCE).buildClient();
        vault.set("Db-Password", "s3cret");
        var returned = new AtomicReference<KeyVaultSecret>();
        var cache = new SinkProbeCache(ring, (name, sink) -> returned.set(
                client.getSecretWithResponse(name, "", SecretCapturePolicy.context(new SecretCapturePolicy.Capture(sink))).getValue()));

        assertEquals("s3cret", decryptString(cache, "Db-Password"));

        assertNotNull(returned.get());
        assertEquals("", returned.get().getValue());
        assertEquals("a tag, not the secret", returned.get().getProperties().getTags().get("value"));
    }

    @Test
    void theAsyncPipeline_CapturesTheValue_AndHandsOnTheBodyWithItBlanked() {
        var pipeline = pipeline();
        vault.set("Db-Password", "s3cret");
        var body = new AtomicReference<String>();
        var captured = new AtomicReference<Boolean>();
        var cache = new SinkProbeCache(ring, (name, sink) -> {
            var capture = new SecretCapturePolicy.Capture(sink);
            try (var response = pipeline.send(getSecret(name), SecretCapturePolicy.context(capture)).block()) {
                body.set(response.getBodyAsString().block());
            }
            captured.set(capture.captured());
        });

        assertEquals("s3cret", decryptString(cache, "Db-Password"));

        assertTrue(captured.get());
        assertTrue(body.get().contains("\"value\":\"\""));
        assertFalse(body.get().contains("s3cret"));
        assertEquals(List.of(false), vault.eagerReads);
    }

    @Test
    void theAsyncPipeline_ZeroesABodyTheHttpClientBuffered() {
        var pipeline = pipeline();
        vault.set("Db-Password", "s3cret");
        vault.alwaysBuffer = true;
        var cache = new SinkProbeCache(ring, (name, sink) -> pipeline
                .send(getSecret(name), SecretCapturePolicy.context(new SecretCapturePolicy.Capture(sink))).block().close());

        assertEquals("s3cret", decryptString(cache, "Db-Password"));

        var buffered = vault.bufferedBodies.get(0);
        assertArrayEquals(new byte[buffered.length], buffered);
    }

    @Test
    void theAsyncPipeline_LeavesAnErrorForTheClient_Buffered() {
        var pipeline = pipeline();
        var status = new AtomicReference<Integer>();
        var body = new AtomicReference<String>();
        var captured = new AtomicReference<Boolean>();
        var cache = new SinkProbeCache(ring, (name, sink) -> {
            var capture = new SecretCapturePolicy.Capture(sink);
            HttpResponse response = pipeline.send(getSecret(name), SecretCapturePolicy.context(capture)).block();
            status.set(response.getStatusCode());
            body.set(response.getBodyAsBinaryData().toString());
            captured.set(capture.captured());
        });

        assertEquals(0, cache.decrypt("missing", new byte[16]));

        assertEquals(404, status.get());
        assertTrue(body.get().contains("SecretNotFound"));
        assertFalse(captured.get());
    }

    @Test
    void theAsyncPipeline_RefusesABodyThatIsNotJson() {
        var pipeline = pipeline();
        vault.rawBody = "not json";
        var cache = new SinkProbeCache(ring, (name, sink) -> pipeline
                .send(getSecret(name), SecretCapturePolicy.context(new SecretCapturePolicy.Capture(sink))).block());

        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));
    }

    @Test
    void aRequestWithoutACapture_PassesThroughUntouched() {
        var pipeline = pipeline();
        vault.set("item", "value");

        try (var response = pipeline.send(getSecret("item")).block()) {
            assertTrue(response instanceof SecretsHttpStub.StubResponse);
            assertTrue(response.getBodyAsString().block().contains("\"value\":\"value\""));
        }
        try (var response = pipeline.sendSync(getSecret("item"), Context.NONE)) {
            assertTrue(response instanceof SecretsHttpStub.StubResponse);
        }
    }
}
