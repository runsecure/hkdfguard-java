package io.github.runsecure.hkdfguard.cache.googlesecretmanager;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.cloud.secretmanager.v1.AccessSecretVersionRequest;
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretManagerServiceGrpc;
import com.google.cloud.secretmanager.v1.SecretManagerServiceSettings;
import com.google.cloud.secretmanager.v1.SecretPayload;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import com.google.protobuf.ByteString;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.ForwardingClientCallListener;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.UnaryOperator;
import java.util.zip.CRC32C;

/**
 * An in-process stand-in for Secret Manager: a gRPC server implementing only AccessSecretVersion
 * (any other call is recorded and answered UNIMPLEMENTED), reached through a real
 * {@link SecretManagerServiceClient}, so the client's own error mapping, retries and cancellation
 * run as they would against Google. Secret IDs are matched exactly, as Google matches them, and
 * responses name the project by its number and carry a CRC32C, as Google's do for payloads added
 * with one.
 * <p>
 * The client's channel carries the {@link ReceiveBufferScrubber}, as the cache's own client does,
 * between two recorders: inside it, {@link #receiveRecorder()} records every buffer the scrubber
 * reads a response into, and outside it every response the client parsed is recorded, so a test can
 * check that both were zeroed. The scrubber reads the message stream itself, which makes the
 * in-process transport serialize the response rather than hand the server's object across.
 */
final class FakeSecretManager implements AutoCloseable {
    static final String PROJECT_ID = "hkdfguard-test";

    // Google answers with the project's number, not the ID it was asked with.
    static final String PROJECT_NUMBER = "123456789012";

    private final Map<String, byte[]> secrets = new ConcurrentHashMap<>();
    private final Server server;
    private final ManagedChannel channel;
    private final SecretManagerServiceClient client;

    /** Every resource name AccessSecretVersion was called with, in order. */
    final List<String> accesses = new CopyOnWriteArrayList<>();

    /** Whether each access was answered on a virtual thread (the in-process server answers on the caller's). */
    final List<Boolean> accessedOnVirtualThread = new CopyOnWriteArrayList<>();

    /** Every other call, by method name. */
    final List<String> unexpectedCalls = new CopyOnWriteArrayList<>();

    /** Every buffer the scrubber read a response into. */
    final List<byte[]> receiveBuffers = new CopyOnWriteArrayList<>();

    /** Every response the client parsed, to check the cache zeroed its payload. */
    final List<AccessSecretVersionResponse> responses = new CopyOnWriteArrayList<>();

    /** When set, AccessSecretVersion fails with this instead of answering. */
    volatile StatusRuntimeException failure;

    /** Runs inside every AccessSecretVersion before it answers, e.g. to hold it open. */
    volatile Runnable onGet;

    /** Rewrites a response before it is sent. */
    volatile UnaryOperator<AccessSecretVersionResponse> tamper;

    /** Never answer, until the client cancels the call. */
    volatile boolean hang;

    /** Counted down when an access arrives. */
    final CountDownLatch received = new CountDownLatch(1);

    /** Counted down when the client cancels a call the fake is hanging on. */
    final CountDownLatch cancelled = new CountDownLatch(1);

    FakeSecretManager() {
        var name = InProcessServerBuilder.generateName();
        try {
            server = InProcessServerBuilder.forName(name).directExecutor().addService(service()).build().start();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        // The last interceptor is the outermost.
        channel = InProcessChannelBuilder.forName(name).directExecutor()
                .intercept(receiveRecorder(), new ReceiveBufferScrubber(), new ResponseRecorder())
                .build();
        try {
            client = SecretManagerServiceClient.create(SecretManagerServiceSettings.newBuilder()
                    .setTransportChannelProvider(FixedTransportChannelProvider.create(GrpcTransportChannel.create(channel)))
                    .setCredentialsProvider(NoCredentialsProvider.create())
                    .build());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** A real Secret Manager client, calling this fake through the scrubber. */
    SecretManagerServiceClient client() {
        return client;
    }

    void set(String secretId, byte[] value) {
        secrets.put(secretId, value);
    }

    void set(String secretId, String value) {
        set(secretId, value.getBytes(StandardCharsets.UTF_8));
    }

    /** The secret ID of every access, in order. */
    List<String> gets() {
        return accesses.stream().map(a -> SecretVersionName.parse(a).getSecret()).toList();
    }

    /**
     * Serves this fake over plaintext HTTP/2 on a loopback port, through gRPC's real (Netty)
     * transport, until closed.
     */
    Server serveOnLoopback() {
        try {
            return NettyServerBuilder.forAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                    .addService(service()).build().start();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Records every array the response marshaller it wraps reads the message into. Placed inside the
     * scrubber, which then reads from the stream it hands over.
     */
    ClientInterceptor receiveRecorder() {
        return new ClientInterceptor() {
            @Override
            public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method, CallOptions options, Channel next) {
                var inner = method.getResponseMarshaller();
                var recording = new MethodDescriptor.Marshaller<RespT>() {
                    @Override
                    public InputStream stream(RespT value) {
                        return inner.stream(value);
                    }

                    @Override
                    public RespT parse(InputStream stream) {
                        return inner.parse(new RecordingStream(stream));
                    }
                };
                return next.newCall(method.toBuilder().setResponseMarshaller(recording).build(), options);
            }
        };
    }

    @Override
    public void close() throws InterruptedException {
        client.close();
        channel.shutdownNow();
        server.shutdownNow();
        client.awaitTermination(5, TimeUnit.SECONDS);
        channel.awaitTermination(5, TimeUnit.SECONDS);
        server.awaitTermination(5, TimeUnit.SECONDS);
    }

    /** The exception for Secret Manager to answer with an error status. */
    static StatusRuntimeException error(Status.Code code, String description) {
        return Status.fromCode(code).withDescription(description).asRuntimeException();
    }

    static long crc32c(byte[] data) {
        var crc = new CRC32C();
        crc.update(data);
        return crc.getValue();
    }

    private io.grpc.ServerServiceDefinition service() {
        return ServerInterceptors.intercept(new Service(), new ServerInterceptor() {
            @Override
            public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers,
                    ServerCallHandler<ReqT, RespT> next) {
                var method = call.getMethodDescriptor().getFullMethodName();
                if (!method.equals(SecretManagerServiceGrpc.getAccessSecretVersionMethod().getFullMethodName()))
                    unexpectedCalls.add(method);
                return next.startCall(call, headers);
            }
        });
    }

    private final class Service extends SecretManagerServiceGrpc.SecretManagerServiceImplBase {
        @Override
        public void accessSecretVersion(AccessSecretVersionRequest request, StreamObserver<AccessSecretVersionResponse> responses) {
            accesses.add(request.getName());
            accessedOnVirtualThread.add(Thread.currentThread().isVirtual());
            received.countDown();
            if (hang) {
                ((ServerCallStreamObserver<AccessSecretVersionResponse>) responses).setOnCancelHandler(cancelled::countDown);
                return;
            }

            AccessSecretVersionResponse response;
            try {
                response = answer(request);
            } catch (StatusRuntimeException e) {
                responses.onError(e);
                return;
            }
            responses.onNext(response);
            responses.onCompleted();
        }
    }

    private AccessSecretVersionResponse answer(AccessSecretVersionRequest request) {
        var hook = onGet;
        if (hook != null)
            hook.run();
        var refusal = failure;
        if (refusal != null)
            throw refusal;

        var name = SecretVersionName.parse(request.getName());
        if (!PROJECT_ID.equals(name.getProject()) || !"latest".equals(name.getSecretVersion()))
            throw error(Status.Code.INVALID_ARGUMENT, "Unexpected resource name " + request.getName() + ".");

        var value = secrets.get(name.getSecret());
        if (value == null)
            throw error(Status.Code.NOT_FOUND, "Secret [projects/" + PROJECT_NUMBER + "/secrets/" + name.getSecret()
                    + "] not found or has no versions.");

        var response = AccessSecretVersionResponse.newBuilder()
                .setName(SecretVersionName.of(PROJECT_NUMBER, name.getSecret(), "1").toString())
                .setPayload(SecretPayload.newBuilder().setData(ByteString.copyFrom(value)).setDataCrc32C(crc32c(value)))
                .build();
        var rewrite = tamper;
        return rewrite != null ? rewrite.apply(response) : response;
    }

    // Records each array it is asked to read into.
    private final class RecordingStream extends FilterInputStream {
        RecordingStream(InputStream in) {
            super(in);
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (receiveBuffers.stream().noneMatch(b -> b == buffer))
                receiveBuffers.add(buffer);
            return super.read(buffer, offset, length);
        }
    }

    // Records every response the client parsed, past the scrubber.
    private final class ResponseRecorder implements ClientInterceptor {
        @Override
        public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method, CallOptions options, Channel next) {
            return new ForwardingClientCall.SimpleForwardingClientCall<>(next.newCall(method, options)) {
                @Override
                public void start(Listener<RespT> listener, Metadata headers) {
                    super.start(new ForwardingClientCallListener.SimpleForwardingClientCallListener<>(listener) {
                        @Override
                        public void onMessage(RespT message) {
                            if (message instanceof AccessSecretVersionResponse response)
                                responses.add(response);
                            super.onMessage(message);
                        }
                    }, headers);
                }
            };
        }
    }
}
