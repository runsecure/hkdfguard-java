package io.github.runsecure.hkdfguard.cache.googlesecretmanager;

import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutureCallback;
import com.google.api.core.ApiFutures;
import com.google.api.gax.grpc.InstantiatingGrpcChannelProvider;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.StatusCode;
import com.google.cloud.secretmanager.v1.AccessSecretVersionRequest;
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretManagerServiceSettings;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import com.google.protobuf.ByteOutput;
import com.google.protobuf.ByteString;
import com.google.protobuf.UnsafeByteOperations;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.cache.RemoteSecretCache;
import io.github.runsecure.hkdfguard.cache.SecretNameMatching;
import io.github.runsecure.hkdfguard.cache.SecretValueSink;
import io.grpc.ManagedChannelBuilder;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.zip.CRC32C;
import org.slf4j.Logger;

/**
 * A {@link io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache} over the secrets in
 * one Google Cloud project's Secret Manager. The first lookup of a name that isn't cached yet reads
 * that one secret's latest version with AccessSecretVersion; fetching, encryption, caching and
 * telemetry are {@link RemoteSecretCache}'s. This class never lists secrets or versions, so the
 * principal needs only {@code secretmanager.versions.access} on the secrets it reads (the Secret
 * Manager Secret Accessor role), never {@code secretmanager.secrets.list}.
 * <p>
 * Names are matched exactly, as Secret Manager matches secret IDs: "Db-Password" and "db-password"
 * are two secrets and two entries. A name Secret Manager can't hold - anything but 1-255 ASCII
 * letters, digits, hyphens and underscores, such as the configuration path "ConnectionStrings:Admin"
 * - is reported missing without a call.
 * <p>
 * A payload holding a JSON object, such as {"username":"app","password":"..."}, is cached whole
 * under the secret's ID and each member under "id#key" - "Db-Login#password" - all from one call
 * (see {@link RemoteSecretCache}).
 * <p>
 * A secret that doesn't exist, or has no versions (NOT_FOUND), or whose value is empty is reported
 * missing. Any other failure (permission denied, a disabled or destroyed latest version, Google
 * unreachable, no credentials) propagates as the client's {@link ApiException}. A payload whose
 * CRC32C doesn't match the checksum Google returns, or a response naming a different secret, is
 * refused with a {@link CryptographicException}.
 * <p>
 * The secret never becomes a String. Its payload arrives as protobuf bytes: the cache encrypts them
 * straight from the {@link ByteString} they were parsed into and then zeroes it, refused or not
 * (reaching its array through {@link UnsafeByteOperations#unsafeWriteTo}, which hands over the array
 * itself). The cache's client also parses each response from a buffer it zeroes afterwards (see
 * ReceiveBufferScrubber), where gRPC's own marshaller would leave it in a reusable thread-local
 * buffer, uncleared. What can't be zeroed is below gRPC's marshaller: the transport's own buffers
 * (Netty's pooled receive buffers, TLS decryption).
 * <p>
 * decryptAsync and findMaxDecryptedLengthAsync fetch through the client's asynchronous call, so a
 * miss doesn't block a thread, and cancelling the lookup that started a fetch cancels the call.
 */
public final class GoogleSecretManagerSecretCacheImpl extends RemoteSecretCache implements AutoCloseable {
    /** The longest ID Secret Manager accepts for a secret. */
    public static final int MAX_SECRET_NAME_LENGTH = 255;

    private final SecretManagerServiceClient client;
    private final boolean ownsClient;
    private final String projectId;

    /**
     * A cache reading secrets through a new client, made from {@code settings} with the
     * ReceiveBufferScrubber added to its channel, which {@link #close} closes.
     *
     * @param settings  the client's settings - credentials, endpoint, retries - e.g. from
     *                  {@link SecretManagerServiceSettings#newBuilder()}. Its transport must be gRPC
     *                  (an {@link InstantiatingGrpcChannelProvider}, the default): the scrubber is
     *                  added through the provider's channel configurator, after any configurator
     *                  and interceptor provider already set, which are kept.
     * @param projectId the project whose secrets are read: its ID or number
     * @param keyRing   supplies the key every fetched secret is encrypted under. Owned by the
     *                  caller: the cache never closes keys.
     * @param logger    optional; see {@link RemoteSecretCache}
     * @throws NullPointerException     settings, projectId or keyRing is null
     * @throws IllegalArgumentException projectId is empty, or holds anything but ASCII letters,
     *                                  digits, hyphens, dots and colons; or the settings' transport
     *                                  isn't an InstantiatingGrpcChannelProvider (HTTP/JSON, or a
     *                                  channel the caller built)
     * @throws IOException              the client could not be created, e.g. no credentials were found
     */
    public GoogleSecretManagerSecretCacheImpl(SecretManagerServiceSettings settings, String projectId, KeyRing keyRing, Logger logger)
            throws IOException {
        super(keyRing, SecretNameMatching.EXACT, logger);
        Objects.requireNonNull(settings, "settings");
        this.projectId = checkProjectId(projectId);
        this.client = SecretManagerServiceClient.create(withScrubber(settings));
        this.ownsClient = true;
    }

    /**
     * A cache over a client the caller built, and closes: the tests', with the ReceiveBufferScrubber
     * already on its channel.
     */
    GoogleSecretManagerSecretCacheImpl(SecretManagerServiceClient client, String projectId, KeyRing keyRing, Logger logger) {
        super(keyRing, SecretNameMatching.EXACT, logger);
        this.client = Objects.requireNonNull(client, "client");
        this.projectId = checkProjectId(projectId);
        this.ownsClient = false;
    }

    /**
     * A cache reading secrets through a new client with the default settings - the global endpoint,
     * over gRPC, signed in with Application Default Credentials - which {@link #close} closes.
     *
     * @param projectId the project whose secrets are read: its ID or number
     * @param keyRing   supplies the key every fetched secret is encrypted under. Owned by the
     *                  caller: the cache never closes keys.
     * @param logger    optional; see {@link RemoteSecretCache}
     * @throws NullPointerException     projectId or keyRing is null
     * @throws IllegalArgumentException projectId isn't a project ID or number
     * @throws IOException              the client could not be created, e.g. no credentials were found
     */
    public static GoogleSecretManagerSecretCacheImpl create(String projectId, KeyRing keyRing, Logger logger) throws IOException {
        return new GoogleSecretManagerSecretCacheImpl(SecretManagerServiceSettings.newBuilder().build(), projectId, keyRing, logger);
    }

    /**
     * Whether Secret Manager accepts name as a secret ID: 1-{@link #MAX_SECRET_NAME_LENGTH} ASCII
     * letters, digits, hyphens and underscores.
     */
    public static boolean isValidSecretName(String name) {
        if (name == null || name.isEmpty() || name.length() > MAX_SECRET_NAME_LENGTH)
            return false;

        for (var i = 0; i < name.length(); i++) {
            var c = name.charAt(i);
            if (!isAsciiLetterOrDigit(c) && c != '-' && c != '_')
                return false;
        }
        return true;
    }

    /** Closes the client this cache created; a client passed in is left open. */
    @Override
    public void close() {
        if (ownsClient)
            client.close();
    }

    /** CRC32C (Castagnoli), as Secret Manager checksums payloads. */
    static long crc32c(ByteString data) {
        var crc = new CRC32C();
        crc.update(data.asReadOnlyByteBuffer());
        return crc.getValue();
    }

    @Override
    protected boolean isValidName(String name) {
        return isValidSecretName(name);
    }

    @Override
    protected void fetch(String name, SecretValueSink value) {
        AccessSecretVersionResponse response;
        try {
            response = client.accessSecretVersion(request(name));
        } catch (ApiException e) {
            if (isNotFound(e))
                return;
            throw e;
        }

        accept(response, name, value);
    }

    @Override
    protected CompletableFuture<Void> fetchAsync(String name, SecretValueSink value) {
        ApiFuture<AccessSecretVersionResponse> call;
        try {
            call = Objects.requireNonNull(client.accessSecretVersionCallable().futureCall(request(name)),
                    "The Secret Manager client returned no future.");
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }

        var fetched = new CompletableFuture<Void>();
        ApiFutures.addCallback(call, new ApiFutureCallback<>() {
            @Override
            public void onSuccess(AccessSecretVersionResponse response) {
                // Cancelled while the answer was on its way: the sink would refuse it anyway.
                if (fetched.isDone()) {
                    scrub(response.getPayload().getData());
                    return;
                }
                try {
                    accept(response, name, value);
                    fetched.complete(null);
                } catch (RuntimeException | Error e) {
                    fetched.completeExceptionally(e);
                }
            }

            @Override
            public void onFailure(Throwable error) {
                if (isNotFound(KeyWrapperFutures.unwrap(error)))
                    fetched.complete(null);
                else
                    fetched.completeExceptionally(error);
            }
        }, Runnable::run);
        fetched.whenComplete((ignored, error) -> {
            if (fetched.isCancelled())
                call.cancel(true);
        });
        return fetched;
    }

    // The settings with the scrubber added to every channel their provider builds. gax offers no way
    // to read a provider's interceptor provider back, so the scrubber goes in through the channel
    // configurator, which gax applies after the interceptor provider's interceptors - leaving those,
    // and any configurator already set, as they were.
    private static SecretManagerServiceSettings withScrubber(SecretManagerServiceSettings settings) throws IOException {
        if (!(settings.getTransportChannelProvider() instanceof InstantiatingGrpcChannelProvider provider))
            throw new IllegalArgumentException("The settings' transport must be gRPC, through an InstantiatingGrpcChannelProvider, so the "
                    + "cache can zero the buffer each response is parsed from; got "
                    + settings.getTransportChannelProvider().getClass().getName() + ".");

        var builder = provider.toBuilder();
        var configurator = builder.getChannelConfigurator();
        var scrubber = new ReceiveBufferScrubber();
        var scrubbing = builder
                .setChannelConfigurator(channel -> configure(configurator == null ? channel : configurator.apply(channel), scrubber))
                .build();
        return settings.toBuilder().setTransportChannelProvider(scrubbing).build();
    }

    private static ManagedChannelBuilder<?> configure(ManagedChannelBuilder<?> builder, ReceiveBufferScrubber scrubber) {
        return builder.intercept(scrubber);
    }

    private static String checkProjectId(String projectId) {
        Objects.requireNonNull(projectId, "projectId");
        if (projectId.isEmpty())
            throw new IllegalArgumentException("The project ID is empty.");

        // Spliced into every resource name, so nothing that could change the path is allowed.
        for (var i = 0; i < projectId.length(); i++) {
            var c = projectId.charAt(i);
            if (!isAsciiLetterOrDigit(c) && c != '-' && c != '.' && c != ':')
                throw new IllegalArgumentException("'" + projectId + "' isn't a Google Cloud project ID or number.");
        }
        return projectId;
    }

    private static boolean isAsciiLetterOrDigit(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }

    private AccessSecretVersionRequest request(String name) {
        return AccessSecretVersionRequest.newBuilder().setName(SecretVersionName.of(projectId, name, "latest").toString()).build();
    }

    private static boolean isNotFound(Throwable error) {
        return error instanceof ApiException e && e.getStatusCode().getCode() == StatusCode.Code.NOT_FOUND;
    }

    // Checks the response, hands its payload to value, and zeroes the payload either way.
    private static void accept(AccessSecretVersionResponse response, String name, SecretValueSink value) {
        var payload = response.getPayload().getData();
        try {
            checkResponse(response, name, payload);

            // Zeroes what it's given. A payload holding a JSON object is cached whole and by key.
            if (!payload.isEmpty())
                value.setBytesWithJsonKeys(exactBytes(payload));
        } finally {
            // Covers a refused response, and a copy's source.
            scrub(payload);
        }
    }

    // The response must be a version of the secret asked for (its project comes back as a number,
    // so only the secret ID can be compared), and match its checksum when it has one.
    private static void checkResponse(AccessSecretVersionResponse response, String name, ByteString payload) {
        var reported = response.getName();
        if (!SecretVersionName.isParsableFrom(reported) || !name.equals(SecretVersionName.parse(reported).getSecret()))
            throw new CryptographicException("Secret Manager answered a request for secret '" + name + "' with '" + reported + "'.");

        if (response.getPayload().hasDataCrc32C() && response.getPayload().getDataCrc32C() != crc32c(payload))
            throw new CryptographicException("The payload of secret '" + name + "' doesn't match its CRC32C: it was corrupted in transit.");
    }

    // The ByteString's own array when it is exactly the payload - as parsing makes it - else an
    // exact copy. Either way the sink zeroes it.
    private static byte[] exactBytes(ByteString bytes) {
        var capture = new Capture();
        writeTo(bytes, capture);
        return capture.exact != null ? capture.exact : bytes.toByteArray();
    }

    /**
     * Zeroes the bytes a ByteString holds. ByteString is immutable to callers, but
     * {@link UnsafeByteOperations#unsafeWriteTo} hands its own arrays to a {@link ByteOutput}, and
     * nothing else holds the one a response was parsed into.
     */
    static void scrub(ByteString bytes) {
        writeTo(bytes, ZEROING);
    }

    private static void writeTo(ByteString bytes, ByteOutput output) {
        try {
            UnsafeByteOperations.unsafeWriteTo(bytes, output);
        } catch (IOException e) {
            throw new UncheckedIOException(e); // neither output throws
        }
    }

    // Finds the array a ByteString holds when it is one array, all of it the ByteString's.
    private static final class Capture extends ByteOutput {
        private byte[] exact;
        private int chunks;

        @Override
        public void write(byte value) {
            chunks++;
            exact = null;
        }

        @Override
        public void write(byte[] value, int offset, int length) {
            exact = ++chunks == 1 && offset == 0 && length == value.length ? value : null;
        }

        @Override
        public void writeLazy(byte[] value, int offset, int length) {
            write(value, offset, length);
        }

        @Override
        public void write(ByteBuffer value) {
            chunks++;
            exact = null;
        }

        @Override
        public void writeLazy(ByteBuffer value) {
            write(value);
        }
    }

    private static final ByteOutput ZEROING = new ByteOutput() {
        @Override
        public void write(byte value) {
            // A single byte by value: nothing to zero.
        }

        @Override
        public void write(byte[] value, int offset, int length) {
            Arrays.fill(value, offset, offset + length, (byte) 0);
        }

        @Override
        public void writeLazy(byte[] value, int offset, int length) {
            Arrays.fill(value, offset, offset + length, (byte) 0);
        }

        @Override
        public void write(ByteBuffer value) {
            zero(value);
        }

        @Override
        public void writeLazy(ByteBuffer value) {
            zero(value);
        }

        private static void zero(ByteBuffer value) {
            if (value.isReadOnly())
                return; // out of reach, like the transport's own buffers (see the class comment)
            while (value.hasRemaining())
                value.put((byte) 0);
        }
    };
}
