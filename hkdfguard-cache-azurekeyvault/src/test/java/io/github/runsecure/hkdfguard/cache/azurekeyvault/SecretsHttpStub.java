package io.github.runsecure.hkdfguard.cache.azurekeyvault;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpClient;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpPipelineCallContext;
import com.azure.core.http.HttpPipelineNextPolicy;
import com.azure.core.http.HttpPipelineNextSyncPolicy;
import com.azure.core.http.HttpPipelinePosition;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.core.http.policy.FixedDelayOptions;
import com.azure.core.http.policy.HttpPipelinePolicy;
import com.azure.core.http.policy.RetryOptions;
import com.azure.core.util.BinaryData;
import com.azure.core.util.Context;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Key Vault's secrets endpoint over HTTP, as an azure-core {@link HttpClient}, behind a real
 * SecretClient with no network: a request without a bearer token gets Key Vault's 401 challenge, and
 * an authorized Get Secret is answered with the secret's JSON (names compared ignoring case, as Key
 * Vault does) or a 404. Any request other than Get Secret - listing secrets or versions among them -
 * is recorded in {@link #unexpectedRequests} and refused.
 * <p>
 * Like azure-core's HTTP clients, it reads a body into an array before handing it over only when the
 * request's Context asks for eager reading, unless {@link #alwaysBuffer} is set. {@link #builder()}
 * also installs a policy recording every body SecretClient was given to deserialize, so a test can
 * check the secret never reached it.
 */
final class SecretsHttpStub implements HttpClient {
    static final String VAULT = "https://hkdfguard-test.vault.azure.net";
    static final String TOKEN = "stub-token";

    /** A credential that always has a token, which this stub accepts. */
    static final TokenCredential CREDENTIAL = request -> Mono.just(new AccessToken(TOKEN, OffsetDateTime.now().plusHours(1)));

    private static final Pattern GET_SECRET = Pattern.compile("/secrets/([^/]+)/?");

    private final Map<String, String> secrets = new ConcurrentSkipListMap<>(String.CASE_INSENSITIVE_ORDER);

    /** The name of every authorized Get Secret, in order. */
    final List<String> gets = new CopyOnWriteArrayList<>();

    /** Whether each authorized Get Secret's Context asked for eager reading (null if it didn't say). */
    final List<Boolean> eagerReads = new CopyOnWriteArrayList<>();

    /** Every other request, as "METHOD path". */
    final List<String> unexpectedRequests = new CopyOnWriteArrayList<>();

    /** Every 200 response body SecretClient deserialized. */
    final List<String> bodiesSeenBySecretClient = new CopyOnWriteArrayList<>();

    /** The array of every 200 body this stub handed over already read into memory. */
    final List<byte[]> bufferedBodies = new CopyOnWriteArrayList<>();

    /** When set, an authorized Get Secret is answered with this status and an error body. */
    volatile Integer failWith;

    /** When set, an authorized Get Secret is answered with this body as it is. */
    volatile String rawBody;

    /** Runs inside every authorized Get Secret before it answers, e.g. to hold it open. */
    volatile Runnable onGet;

    /** Hands every body over already read into an array, whatever the Context asks. */
    volatile boolean alwaysBuffer;

    void set(String name, String value) {
        secrets.put(name, value);
    }

    /** A client builder calling this stub, without retries, recording the bodies SecretClient sees. */
    SecretClientBuilder builder() {
        return new SecretClientBuilder()
                .vaultUrl(VAULT)
                .credential(CREDENTIAL)
                .httpClient(this)
                .retryOptions(new RetryOptions(new FixedDelayOptions(0, Duration.ZERO)))
                .addPolicy(new BodyRecorder());
    }

    @Override
    public Mono<HttpResponse> send(HttpRequest request) {
        return send(request, Context.NONE);
    }

    @Override
    public Mono<HttpResponse> send(HttpRequest request, Context context) {
        return Mono.fromSupplier(() -> answer(request, context));
    }

    @Override
    public HttpResponse sendSync(HttpRequest request, Context context) {
        return answer(request, context);
    }

    private HttpResponse answer(HttpRequest request, Context context) {
        var authorization = request.getHeaders().getValue(HttpHeaderName.AUTHORIZATION);
        if (authorization == null) {
            return new StubResponse(request, 401, new HttpHeaders().set(HttpHeaderName.WWW_AUTHENTICATE,
                    "Bearer authorization=\"https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000\", resource=\"https://vault.azure.net\""),
                    new byte[0], true);
        }
        if (!("Bearer " + TOKEN).equals(authorization))
            return error(request, 401, "Unauthorized");

        var url = request.getUrl();
        var path = GET_SECRET.matcher(url.getPath());
        if (request.getHttpMethod() != HttpMethod.GET || !("https://" + url.getHost()).equals(VAULT) || !path.matches()) {
            unexpectedRequests.add(request.getHttpMethod() + " " + url.getPath());
            return error(request, 403, "Forbidden");
        }

        var name = path.group(1);
        gets.add(name);
        var eager = context.getData(SecretCapturePolicy.EAGERLY_READ_RESPONSE).orElse(null);
        eagerReads.add(eager instanceof Boolean b ? b : null);
        var run = onGet;
        if (run != null)
            run.run();

        if (failWith != null)
            return error(request, failWith, failWith == 403 ? "Forbidden" : "InternalServerError");

        var buffered = alwaysBuffer || Boolean.TRUE.equals(eager);
        var raw = rawBody;
        if (raw != null)
            return ok(request, raw, buffered);

        var value = secrets.get(name);
        if (value == null)
            return error(request, 404, "SecretNotFound");

        return ok(request, "{\"value\":" + quote(value)
                + ",\"id\":\"" + VAULT + "/secrets/" + name + "/0123456789abcdef0123456789abcdef\""
                + ",\"attributes\":{\"enabled\":true,\"created\":1700000000,\"updated\":1700000000,\"recoveryLevel\":\"Recoverable+Purgeable\"}"
                + ",\"tags\":{\"value\":\"a tag, not the secret\"}}", buffered);
    }

    private HttpResponse ok(HttpRequest request, String json, boolean buffered) {
        var body = json.getBytes(StandardCharsets.UTF_8);
        if (buffered)
            bufferedBodies.add(body);
        return new StubResponse(request, 200, jsonHeaders(body), body, buffered);
    }

    /** Key Vault's error response: {@code {"error":{"code":...,"message":...}}}. */
    private static HttpResponse error(HttpRequest request, int status, String code) {
        var body = ("{\"error\":{\"code\":\"" + code + "\",\"message\":\"" + code + " from the stub vault.\"}}").getBytes(StandardCharsets.UTF_8);
        return new StubResponse(request, status, jsonHeaders(body), body, false);
    }

    private static HttpHeaders jsonHeaders(byte[] body) {
        return new HttpHeaders()
                .set(HttpHeaderName.CONTENT_TYPE, "application/json; charset=utf-8")
                .set(HttpHeaderName.CONTENT_LENGTH, Integer.toString(body.length));
    }

    static String quote(String value) {
        var json = new StringBuilder("\"");
        for (var i = 0; i < value.length(); i++) {
            var c = value.charAt(i);
            switch (c) {
                case '"' -> json.append("\\\"");
                case '\\' -> json.append("\\\\");
                case '\n' -> json.append("\\n");
                default -> {
                    if (c < 0x20)
                        json.append(String.format("\\u%04x", (int) c));
                    else
                        json.append(c);
                }
            }
        }
        return json.append('"').toString();
    }

    /** A canned response: a body read into memory, or one handed over as a stream. */
    static final class StubResponse extends HttpResponse {
        private final int status;
        private final HttpHeaders headers;
        private final byte[] body;
        private final boolean buffered;

        StubResponse(HttpRequest request, int status, HttpHeaders headers, byte[] body, boolean buffered) {
            super(request);
            this.status = status;
            this.headers = headers;
            this.body = body;
            this.buffered = buffered;
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
            return Flux.defer(() -> Flux.just(ByteBuffer.wrap(buffered ? body : body.clone())));
        }

        // As azure-core's clients do: a buffered body's own array.
        @Override
        public Mono<byte[]> getBodyAsByteArray() {
            return Mono.fromSupplier(() -> buffered ? body : body.clone());
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
            return buffered ? BinaryData.fromBytes(body) : BinaryData.fromStream(new ByteArrayInputStream(body.clone()));
        }
    }

    // Outermost, so it sees each response exactly as SecretClient will deserialize it.
    private final class BodyRecorder implements HttpPipelinePolicy {
        @Override
        public HttpPipelinePosition getPipelinePosition() {
            return HttpPipelinePosition.PER_CALL;
        }

        @Override
        public HttpResponse processSync(HttpPipelineCallContext context, HttpPipelineNextSyncPolicy next) {
            return record(next.processSync());
        }

        @Override
        public Mono<HttpResponse> process(HttpPipelineCallContext context, HttpPipelineNextPolicy next) {
            return next.process().map(this::record);
        }

        private HttpResponse record(HttpResponse response) {
            if (response.getStatusCode() != 200)
                return response;

            var buffered = response.getBodyAsBinaryData().isReplayable() ? response : response.buffer();
            bodiesSeenBySecretClient.add(buffered.getBodyAsBinaryData().toString());
            return buffered;
        }
    }
}
