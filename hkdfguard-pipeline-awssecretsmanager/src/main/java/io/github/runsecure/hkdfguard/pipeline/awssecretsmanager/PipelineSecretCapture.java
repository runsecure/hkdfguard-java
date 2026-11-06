package io.github.runsecure.hkdfguard.pipeline.awssecretsmanager;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.reactivestreams.Publisher;
import software.amazon.awssdk.core.SdkPlugin;
import software.amazon.awssdk.core.SdkServiceClientConfiguration;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

/**
 * Hands one GetSecretValue's response body to {@link #capture}, and the SDK's unmarshaller an empty
 * object in its place. It is a plugin on that request alone, as hkdfguard-cache-awssecretsmanager's
 * capture is, so the application's client is left as it is: for that request the SDK applies it to
 * a copy of the client's configuration, adding it as an interceptor, which replaces a successful
 * response's body with {@link CapturingPublisher}'s. An error response (4xx, 5xx) holds no secret and
 * passes through.
 */
final class PipelineSecretCapture implements SdkPlugin, ExecutionInterceptor {
    /** Takes a successful GetSecretValue response body, body[0, length), in an array zeroed once it returns. */
    @FunctionalInterface
    interface BodyCapture {
        void capture(byte[] body, int length);
    }

    private static final byte[] EMPTY_OBJECT = "{}".getBytes(StandardCharsets.US_ASCII);

    private final BodyCapture body;
    private final AtomicReference<RuntimeException> failure = new AtomicReference<>();
    private volatile boolean captured;

    PipelineSecretCapture(BodyCapture body) {
        this.body = body;
    }

    @Override
    public void configureClient(SdkServiceClientConfiguration.Builder config) {
        var override = config.overrideConfiguration().toBuilder().addExecutionInterceptor(this).build();
        config.overrideConfiguration(override);
    }

    @Override
    public Optional<Publisher<ByteBuffer>> modifyAsyncHttpResponseContent(Context.ModifyHttpResponse context, ExecutionAttributes executionAttributes) {
        var response = context.responsePublisher();
        if (response.isEmpty() || !context.httpResponse().isSuccessful() || !(context.request() instanceof GetSecretValueRequest))
            return response;
        return Optional.of(new CapturingPublisher(response.get(), this));
    }

    /**
     * Hands the body in body's first length bytes to the capture and returns what the SDK is given in
     * its place: "{}". body is left for the caller to zero.
     */
    byte[] capture(byte[] response, int length) {
        captured = true;
        try {
            body.capture(response, length);
            return EMPTY_OBJECT.clone();
        } catch (RuntimeException e) {
            failed(e);
            throw e;
        }
    }

    /** Records why a response body was refused; the first reason wins. */
    void failed(RuntimeException e) {
        failure.compareAndSet(null, e);
    }

    /** Whether a successful response's body reached {@link #capture}. */
    boolean captured() {
        return captured;
    }

    /** Why a response body was refused, or null. */
    RuntimeException failure() {
        return failure.get();
    }
}
