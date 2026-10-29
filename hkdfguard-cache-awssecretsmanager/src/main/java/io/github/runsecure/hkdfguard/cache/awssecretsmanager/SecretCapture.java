package io.github.runsecure.hkdfguard.cache.awssecretsmanager;

import io.github.runsecure.hkdfguard.cache.SecretJsonBody;
import io.github.runsecure.hkdfguard.cache.SecretValueSink;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
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
 * Takes one GetSecretValue's secret out of its response body, for {@link #sink}. It is a plugin on
 * that request alone, so the application's client is left as it is: for that request the SDK
 * applies it to a copy of the client's configuration, adding it as an interceptor, which replaces a
 * successful response's body with {@link CapturingPublisher}'s - the same body with SecretString and
 * SecretBinary replaced by "". An error response (4xx, 5xx) holds no secret and passes through.
 */
final class SecretCapture implements SdkPlugin, ExecutionInterceptor {
    static final String TEXT_PROPERTY = "SecretString";
    static final String BINARY_PROPERTY = "SecretBinary";

    private final SecretValueSink sink;
    private final AtomicReference<RuntimeException> failure = new AtomicReference<>();
    private volatile boolean captured;

    SecretCapture(SecretValueSink sink) {
        this.sink = sink;
    }

    @Override
    public void configureClient(SdkServiceClientConfiguration.Builder config) {
        var override = config.overrideConfiguration().toBuilder().addExecutionInterceptor(this).build();
        config.overrideConfiguration(override);
    }

    @Override
    public Optional<Publisher<ByteBuffer>> modifyAsyncHttpResponseContent(Context.ModifyHttpResponse context, ExecutionAttributes executionAttributes) {
        var body = context.responsePublisher();
        if (body.isEmpty() || !context.httpResponse().isSuccessful() || !(context.request() instanceof GetSecretValueRequest))
            return body;
        return Optional.of(new CapturingPublisher(body.get(), this));
    }

    /**
     * Hands the secret in body's first length bytes to the sink and returns the body without it.
     * body is left for the caller to zero.
     */
    byte[] capture(byte[] body, int length) {
        captured = true;
        try {
            return SecretJsonBody.capture(new ByteArrayInputStream(body, 0, length), sink, TEXT_PROPERTY, BINARY_PROPERTY);
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
