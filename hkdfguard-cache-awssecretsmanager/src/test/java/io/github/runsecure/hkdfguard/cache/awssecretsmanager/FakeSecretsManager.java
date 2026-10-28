package io.github.runsecure.hkdfguard.cache.awssecretsmanager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.awscore.retry.AwsRetryStrategy;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.http.async.AsyncExecuteRequest;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;

/**
 * Secrets Manager's JSON 1.1 endpoint, as an asynchronous HTTP client under a real
 * SecretsManagerAsyncClient - no network: a GetSecretValue is answered with the secret (names
 * matched exactly, as AWS matches them) or ResourceNotFoundException. Any other operation -
 * ListSecrets and BatchGetSecretValue among them - is recorded in {@link #unexpectedOperations} and
 * refused. Each body is sent in small chunks, each its own writable array, kept in {@link #bodies}
 * so a test can see whether it was zeroed.
 */
final class FakeSecretsManager implements SdkAsyncHttpClient {
    private static final Pattern SECRET_ID = Pattern.compile("\"SecretId\"\\s*:\\s*\"([^\"\\\\]*)\"");

    private final Map<String, String> secrets = new ConcurrentHashMap<>();
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    /** Every SecretId GetSecretValue was called with, in order. */
    final ConcurrentLinkedQueue<String> gets = new ConcurrentLinkedQueue<>();

    /** Every other operation called. */
    final ConcurrentLinkedQueue<String> unexpectedOperations = new ConcurrentLinkedQueue<>();

    /** The chunks of every successful response body sent, per response, in order. */
    final ConcurrentLinkedQueue<List<byte[]>> bodies = new ConcurrentLinkedQueue<>();

    /** The future execute returned for every request, in order. */
    final ConcurrentLinkedQueue<CompletableFuture<Void>> calls = new ConcurrentLinkedQueue<>();

    /** When set, GetSecretValue fails with this AWS error type and HTTP status. */
    volatile String failWith;
    volatile int failStatus;

    /** When set, GetSecretValue is answered with this body as it is. */
    volatile byte[] rawBody;

    /** Runs inside every GetSecretValue before it answers, e.g. to hold it open. */
    volatile Runnable onGet;

    /** The length of each chunk a body is sent in. */
    volatile int chunkLength = 7;

    void setString(String name, String value) {
        secrets.put(name, "\"SecretString\":" + json(value) + ",");
    }

    void setBinary(String name, byte[] value) {
        secrets.put(name, "\"SecretBinary\":\"" + Base64.getEncoder().encodeToString(value) + "\",");
    }

    void setEmpty(String name) {
        secrets.put(name, "");
    }

    void failWith(String type, int status) {
        failWith = type;
        failStatus = status;
    }

    /** A client sending every request here, without retries, with interceptors of the application's own. */
    SecretsManagerAsyncClient client(AwsCredentialsProvider credentials, ExecutionInterceptor... interceptors) {
        return SecretsManagerAsyncClient.builder()
                .region(Region.US_EAST_1)
                .credentialsProvider(credentials != null ? credentials : AnonymousCredentialsProvider.create())
                .httpClient(this)
                .overrideConfiguration(o -> {
                    o.retryStrategy(AwsRetryStrategy.doNotRetry());
                    for (var interceptor : interceptors)
                        o.addExecutionInterceptor(interceptor);
                })
                .build();
    }

    @Override
    public CompletableFuture<Void> execute(AsyncExecuteRequest request) {
        var done = new CompletableFuture<Void>();
        calls.add(done);
        executor.execute(() -> {
            try {
                answer(request, done);
            } catch (Throwable e) {
                request.responseHandler().onError(e);
                done.completeExceptionally(e);
            }
        });
        return done;
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }

    private void answer(AsyncExecuteRequest request, CompletableFuture<Void> done) {
        var http = request.request();
        var operation = http.firstMatchingHeader("X-Amz-Target").orElse("");
        if (!operation.equals("secretsmanager.GetSecretValue")) {
            unexpectedOperations.add(operation);
            error(request, done, "AccessDeniedException", 400);
            return;
        }

        assertEquals("POST", http.method().name());
        assertTrue(http.firstMatchingHeader("Content-Type").orElse("").startsWith("application/x-amz-json-1.1"));
        var body = new String(readAll(request.requestContentPublisher()), StandardCharsets.UTF_8);
        assertFalse(body.contains("VersionId"), body);
        assertFalse(body.contains("VersionStage"), body);
        var matcher = SECRET_ID.matcher(body);
        assertTrue(matcher.find(), body);
        var name = matcher.group(1);

        gets.add(name);
        var hold = onGet;
        if (hold != null)
            hold.run();
        if (done.isDone())
            return;

        var failure = failWith;
        if (failure != null) {
            error(request, done, failure, failStatus);
            return;
        }
        var raw = rawBody;
        if (raw != null) {
            respond(request, done, 200, raw.clone(), true);
            return;
        }
        var value = secrets.get(name);
        if (value == null) {
            error(request, done, "ResourceNotFoundException", 400);
            return;
        }

        var response = "{\"ARN\":" + json("arn:aws:secretsmanager:us-east-1:123456789012:secret:" + name + "-AbCdEf")
                + ",\"Name\":" + json(name) + "," + value
                + "\"VersionId\":\"a1b2c3d4-5678-90ab-cdef-EXAMPLE11111\",\"VersionStages\":[\"AWSCURRENT\"],\"CreatedDate\":1700000000.0}";
        respond(request, done, 200, response.getBytes(StandardCharsets.UTF_8), true);
    }

    private void error(AsyncExecuteRequest request, CompletableFuture<Void> done, String type, int status) {
        var body = "{\"__type\":" + json(type) + ",\"Message\":" + json(type + " in a test.") + "}";
        respond(request, done, status, body.getBytes(StandardCharsets.UTF_8), false);
    }

    private void respond(AsyncExecuteRequest request, CompletableFuture<Void> done, int status, byte[] body, boolean keep) {
        var builder = SdkHttpResponse.builder()
                .statusCode(status)
                .putHeader("Content-Type", "application/x-amz-json-1.1")
                .putHeader("Content-Length", Integer.toString(body.length))
                .putHeader("x-amzn-RequestId", "request-1");
        if (status >= 300)
            builder.putHeader("x-amzn-ErrorType", new String(body, StandardCharsets.UTF_8).replaceAll(".*\"__type\":\"([^\"]*)\".*", "$1"));

        var chunks = new ArrayList<byte[]>();
        for (var offset = 0; offset < body.length; offset += chunkLength)
            chunks.add(java.util.Arrays.copyOfRange(body, offset, Math.min(body.length, offset + chunkLength)));
        java.util.Arrays.fill(body, (byte) 0);
        if (keep)
            bodies.add(chunks);

        var handler = request.responseHandler();
        handler.onHeaders(builder.build());
        handler.onStream(new ChunkPublisher(chunks, done));
    }

    static String json(String value) {
        var builder = new StringBuilder("\"");
        for (var i = 0; i < value.length(); i++) {
            var c = value.charAt(i);
            switch (c) {
                case '"' -> builder.append("\\\"");
                case '\\' -> builder.append("\\\\");
                case '\n' -> builder.append("\\n");
                default -> {
                    if (c < 0x20)
                        builder.append(String.format("\\u%04x", (int) c));
                    else
                        builder.append(c);
                }
            }
        }
        return builder.append('"').toString();
    }

    private static byte[] readAll(Publisher<ByteBuffer> publisher) {
        var out = new ByteArrayOutputStream();
        var finished = new CompletableFuture<Void>();
        publisher.subscribe(new Subscriber<ByteBuffer>() {
            @Override
            public void onSubscribe(Subscription s) {
                s.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer buffer) {
                var bytes = new byte[buffer.remaining()];
                buffer.get(bytes);
                synchronized (out) {
                    out.writeBytes(bytes);
                }
            }

            @Override
            public void onError(Throwable t) {
                finished.completeExceptionally(t);
            }

            @Override
            public void onComplete() {
                finished.complete(null);
            }
        });
        Futures.await(finished);
        synchronized (out) {
            return out.toByteArray();
        }
    }

    /** Publishes chunks as writable buffers, honouring demand, then completes done. */
    private static final class ChunkPublisher implements Publisher<ByteBuffer> {
        private final List<byte[]> chunks;
        private final CompletableFuture<Void> done;

        ChunkPublisher(List<byte[]> chunks, CompletableFuture<Void> done) {
            this.chunks = chunks;
            this.done = done;
        }

        @Override
        public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
            subscriber.onSubscribe(new Subscription() {
                private long demand;
                private int next;
                private boolean emitting;
                private boolean stopped;

                @Override
                public void request(long n) {
                    synchronized (this) {
                        demand = demand + n < 0 ? Long.MAX_VALUE : demand + n;
                        if (emitting)
                            return;
                        emitting = true;
                    }
                    while (true) {
                        ByteBuffer chunk = null;
                        var complete = false;
                        synchronized (this) {
                            if (stopped) {
                                emitting = false;
                                return;
                            }
                            if (next == chunks.size()) {
                                stopped = true;
                                complete = true;
                            } else if (demand > 0) {
                                demand--;
                                chunk = ByteBuffer.wrap(chunks.get(next++));
                            } else {
                                emitting = false;
                                return;
                            }
                        }
                        if (complete) {
                            subscriber.onComplete();
                            done.complete(null);
                            return;
                        }
                        subscriber.onNext(chunk);
                    }
                }

                @Override
                public synchronized void cancel() {
                    stopped = true;
                    done.cancel(false);
                }
            });
        }
    }
}
