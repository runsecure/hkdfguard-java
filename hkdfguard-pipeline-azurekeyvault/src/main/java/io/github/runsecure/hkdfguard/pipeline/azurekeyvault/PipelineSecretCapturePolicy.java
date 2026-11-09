package io.github.runsecure.hkdfguard.pipeline.azurekeyvault;

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
import io.github.runsecure.hkdfguard.pipeline.ResponseBody;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Takes the secret out of a Get Secret response before SecretClient can turn it into a String, as
 * hkdfguard-cache-azurekeyvault's capture policy does. Acts only on a request whose Context holds a
 * {@link Capture} (see {@link #context}); every other request passes through untouched, so a client
 * built from the same builder reads secrets as usual.
 * <p>
 * For a capturing request it turns azure-core's eager reading of the response off, so the HTTP
 * client hands over the body as a stream rather than reading it into an array of its own first. A
 * 200's body is then read straight into a {@link ResponseBody}, handed to the capture and zeroed,
 * and SecretClient is given an empty object in its place - nothing the writer needs is in the
 * response, as with the .NET pipeline writer. An HTTP client that buffers the body regardless hands
 * it over as an array this policy can reach, and that array is zeroed once the capture has it. Any
 * other status is buffered as azure-core would have buffered it, for SecretClient's error handling.
 */
final class PipelineSecretCapturePolicy implements HttpPipelinePolicy {
    /** The Context key a read's {@link Capture} travels under. */
    static final String CAPTURE_KEY = "io.github.runsecure.hkdfguard.pipeline.azurekeyvault.capture";

    // azure-core's own key (HttpUtils.AZURE_EAGERLY_READ_RESPONSE, which isn't exported): a REST
    // method that sets it true has the HTTP client read the whole body into an array.
    static final String EAGERLY_READ_RESPONSE = "azure-eagerly-read-response";

    static final PipelineSecretCapturePolicy INSTANCE = new PipelineSecretCapturePolicy();

    private static final byte[] EMPTY_OBJECT = "{}".getBytes(StandardCharsets.US_ASCII);

    private PipelineSecretCapturePolicy() {
    }

    /** Takes a successful Get Secret response body, body[0, length), in an array zeroed once it returns. */
    @FunctionalInterface
    interface BodyCapture {
        void capture(byte[] body, int length);
    }

    /** One read's capture, and whether its response reached it. */
    static final class Capture {
        private final BodyCapture body;
        private volatile boolean captured;

        Capture(BodyCapture body) {
            this.body = Objects.requireNonNull(body, "body");
        }

        /** Whether a 200 response passed through this policy, so its body went to the capture. */
        boolean captured() {
            return captured;
        }

        private void take(byte[] response, int length) {
            body.capture(response, length);
            captured = true;
        }
    }

    /** The Context of a request whose response body goes to {@code capture}. */
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
            if (body.isReplayable()) {
                // Already in memory: azure-core's own array, for a body the HTTP client buffered.
                var bytes = body.toBytes();
                try {
                    capture.take(bytes, bytes.length);
                } finally {
                    ArrayUtility.zeroMemory(bytes);
                }
            } else {
                try (var stream = body.toStream(); var read = ResponseBody.read(stream)) {
                    capture.take(read.buffer(), read.length());
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
            return new CapturedResponse(response);
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
                    capture.take(bytes, bytes.length);
                    return (HttpResponse) new CapturedResponse(response);
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

    /** A response as received, with the body SecretClient may see: an empty object. */
    private static final class CapturedResponse extends HttpResponse {
        private final int status;
        private final HttpHeaders headers;

        CapturedResponse(HttpResponse response) {
            super(response.getRequest());
            this.status = response.getStatusCode();
            this.headers = new HttpHeaders(response.getHeaders());
            if (headers.get(HttpHeaderName.CONTENT_LENGTH) != null)
                headers.set(HttpHeaderName.CONTENT_LENGTH, Integer.toString(EMPTY_OBJECT.length));
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
            return Flux.defer(() -> Flux.just(ByteBuffer.wrap(EMPTY_OBJECT).asReadOnlyBuffer()));
        }

        @Override
        public Mono<byte[]> getBodyAsByteArray() {
            return Mono.fromSupplier(EMPTY_OBJECT::clone);
        }

        @Override
        public Mono<String> getBodyAsString() {
            return getBodyAsString(StandardCharsets.UTF_8);
        }

        @Override
        public Mono<String> getBodyAsString(Charset charset) {
            return Mono.fromSupplier(() -> new String(EMPTY_OBJECT, charset));
        }

        @Override
        public BinaryData getBodyAsBinaryData() {
            return BinaryData.fromBytes(EMPTY_OBJECT.clone());
        }
    }
}
