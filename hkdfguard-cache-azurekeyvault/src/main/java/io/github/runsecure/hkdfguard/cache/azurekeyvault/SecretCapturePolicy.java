package io.github.runsecure.hkdfguard.cache.azurekeyvault;

import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpPipelineCallContext;
import com.azure.core.http.HttpPipelineNextPolicy;
import com.azure.core.http.HttpPipelineNextSyncPolicy;
import com.azure.core.http.HttpPipelinePosition;
import com.azure.core.http.HttpResponse;
import com.azure.core.http.policy.HttpPipelinePolicy;
import com.azure.core.util.BinaryData;
import com.azure.core.util.Context;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.cache.SecretJsonBody;
import io.github.runsecure.hkdfguard.cache.SecretValueSink;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Takes the secret out of a Get Secret response before SecretClient can turn it into a String. Acts
 * only on a request whose Context holds a {@link Capture} (see {@link #context}); every other request
 * passes through untouched, so a client built from the same builder reads secrets as usual.
 * <p>
 * For a capturing request it turns azure-core's eager reading of the response off, so the HTTP
 * client hands over the body as a stream rather than reading it into an array of its own first.
 * (SecretClient's Get Secret doesn't ask for eager reading today; the policy says so explicitly,
 * so that a later SDK which does can't buffer the secret out of reach.) A 200's body is then read
 * straight into {@link SecretJsonBody}'s buffer, its {@code value} handed to the capture's sink, and
 * SecretClient is given the body with {@code value} blanked. An HTTP client that buffers the body
 * regardless hands it over as an array this policy can reach, and that array is zeroed once the
 * value is taken out. Any other status is buffered as azure-core would have buffered it, for
 * SecretClient's error handling.
 */
final class SecretCapturePolicy implements HttpPipelinePolicy {
    /** The Context key a fetch's {@link Capture} travels under. */
    static final String CAPTURE_KEY = "io.github.runsecure.hkdfguard.cache.azurekeyvault.capture";

    // azure-core's own key (HttpUtils.AZURE_EAGERLY_READ_RESPONSE, which isn't exported): a REST
    // method that sets it true has the HTTP client read the whole body into an array.
    static final String EAGERLY_READ_RESPONSE = "azure-eagerly-read-response";

    static final SecretCapturePolicy INSTANCE = new SecretCapturePolicy();

    private SecretCapturePolicy() {
    }

    /** One fetch's sink, and whether its response reached it. */
    static final class Capture {
        private final SecretValueSink sink;
        private volatile boolean captured;

        Capture(SecretValueSink sink) {
            this.sink = Objects.requireNonNull(sink, "sink");
        }

        /** Whether a 200 response passed through this policy, so its value, if any, went to the sink. */
        boolean captured() {
            return captured;
        }
    }

    /** The Context of a request whose secret goes to {@code capture}. */
    static Context context(Capture capture) {
        return new Context(CAPTURE_KEY, capture);
    }

    @Override
    public HttpPipelinePosition getPipelinePosition() {
        return HttpPipelinePosition.PER_RETRY;
    }

    @Override
    public HttpResponse processSync(HttpPipelineCallContext context, HttpPipelineNextSyncPolicy next) {
        var capture = streamed(context);
        var response = next.processSync();
        if (capture == null)
            return response;
        if (response.getStatusCode() != 200)
            return response.buffer();

        try (response) {
            var body = response.getBodyAsBinaryData();
            byte[] redacted;
            if (body.isReplayable()) {
                // Already in memory: azure-core's own array, for a body the HTTP client buffered.
                var bytes = body.toBytes();
                try {
                    redacted = SecretJsonBody.capture(new ByteArrayInputStream(bytes), capture.sink, "value");
                } finally {
                    ArrayUtility.zeroMemory(bytes);
                }
            } else {
                redacted = SecretJsonBody.capture(body.toStream(), capture.sink, "value");
            }
            capture.captured = true;
            return new CapturedResponse(response, redacted);
        }
    }

    @Override
    public Mono<HttpResponse> process(HttpPipelineCallContext context, HttpPipelineNextPolicy next) {
        var capture = streamed(context);
        if (capture == null)
            return next.process();

        return next.process().flatMap(response -> {
            if (response.getStatusCode() != 200)
                return Mono.just(response.buffer());

            // The body's array is the HTTP client's buffer, or one aggregated for this call; either
            // way it is this policy's to zero.
            return response.getBodyAsByteArray().defaultIfEmpty(new byte[0]).map(bytes -> {
                try (response) {
                    var redacted = SecretJsonBody.capture(new ByteArrayInputStream(bytes), capture.sink, "value");
                    capture.captured = true;
                    return (HttpResponse) new CapturedResponse(response, redacted);
                } finally {
                    ArrayUtility.zeroMemory(bytes);
                }
            });
        });
    }

    // The request's capture, if it has one, its response then left unbuffered.
    private static Capture streamed(HttpPipelineCallContext context) {
        if (!(context.getData(CAPTURE_KEY).orElse(null) instanceof Capture capture))
            return null;

        context.setData(EAGERLY_READ_RESPONSE, false);
        return capture;
    }

    /** A response as received, with the body SecretClient may see: the secret blanked. */
    private static final class CapturedResponse extends HttpResponse {
        private final int status;
        private final HttpHeaders headers;
        private final byte[] body;

        CapturedResponse(HttpResponse response, byte[] body) {
            super(response.getRequest());
            this.status = response.getStatusCode();
            this.headers = new HttpHeaders(response.getHeaders());
            if (headers.get(HttpHeaderName.CONTENT_LENGTH) != null)
                headers.set(HttpHeaderName.CONTENT_LENGTH, Integer.toString(body.length));
            this.body = body;
        }

        @Override
        public int getStatusCode() {
            return status;
        }

        @Override
        @Deprecated
        public String getHeaderValue(String name) {
            return headers.getValue(HttpHeaderName.fromString(name));
        }

        @Override
        public HttpHeaders getHeaders() {
            return headers;
        }

        @Override
        public Flux<ByteBuffer> getBody() {
            return Flux.defer(() -> Flux.just(ByteBuffer.wrap(body).asReadOnlyBuffer()));
        }

        @Override
        public Mono<byte[]> getBodyAsByteArray() {
            return Mono.fromSupplier(body::clone);
        }

        @Override
        public Mono<String> getBodyAsString() {
            return getBodyAsString(StandardCharsets.UTF_8);
        }

        @Override
        public Mono<String> getBodyAsString(Charset charset) {
            return Mono.fromSupplier(() -> new String(body, charset));
        }

        @Override
        public BinaryData getBodyAsBinaryData() {
            return BinaryData.fromBytes(body);
        }
    }
}
