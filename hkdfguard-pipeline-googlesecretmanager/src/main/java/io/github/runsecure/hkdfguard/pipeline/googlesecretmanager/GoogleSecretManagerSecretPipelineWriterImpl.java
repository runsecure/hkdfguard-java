package io.github.runsecure.hkdfguard.pipeline.googlesecretmanager;

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
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.pipeline.SecretPipelineWriterBase;
import io.github.runsecure.hkdfguard.pipeline.SecretRequest;
import io.grpc.ManagedChannelBuilder;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.zip.CRC32C;

/**
 * The end of a provisioning pipeline: pulls a fixed list of secrets from one Google Cloud project's
 * Secret Manager, encrypts each with a {@link PipelineDataProtector} as soon as it is read, and
 * writes them out as one file per secret - the folder layout FilePerSecretCacheImpl reads at runtime.
 * It is independent of hkdfguard-cache-googlesecretmanager's runtime cache, and of any key ring, with
 * its own client. Naming, encrypting, keeping and writing are {@link SecretPipelineWriterBase}'s.
 * <pre>{@code
 * try (var protector = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), 3);
 *         var writer = GoogleSecretManagerSecretPipelineWriterImpl.create("my-project", protector,
 *                 List.of("db-login#username", "db-login#password", "api-key"))) {
 *     writer.pullSecretsAsync().join();
 *     writer.writeProtectedSecretFiles(Path.of("C:\\HkdfGuardSecrets\\myapp"));
 *     // Then hand protector.getKeyAsBase64() to the wrap tool, and register the key at version 3.
 * }
 * }</pre>
 * <p>
 * A secret name is a Secret Manager secret ID - 1-255 ASCII letters, digits, hyphens and underscores
 * - optionally with a key after '#': "api-key" reads the latest version's whole payload, and
 * "db-login#password" the password member of a payload holding a JSON object (written as api-key and
 * db-login__password). A member's string is read as its text; a number, true or false as its JSON
 * text. A payload that isn't UTF-8 text is refused with an {@link InvalidSecretDataException}: the
 * protector encrypts text. Each secret's latest version is read with AccessSecretVersion, so the
 * principal needs only {@code secretmanager.versions.access} (the Secret Manager Secret Accessor
 * role), never a list permission. On GKE, Workload Identity supplies the application default
 * credential. A secret that doesn't exist, or has no versions (NOT_FOUND), is missing; any other
 * failure (permission denied, a disabled or destroyed latest version, Google unreachable, no
 * credentials) fails the pull as the client's {@link ApiException}.
 * <p>
 * A payload whose CRC32C doesn't match the checksum Google returns, or a response naming a
 * different secret, is refused with a {@link CryptographicException}. The payload is encrypted
 * straight from the {@link ByteString} gRPC parsed it into, which is then zeroed, refused or not; the
 * writer's client also parses each response from a buffer it zeroes afterwards (see
 * ReceiveBufferScrubber), as hkdfguard-cache-googlesecretmanager's does. What can't be zeroed is
 * below gRPC's marshaller: the transport's own buffers. Each read goes through the client's
 * asynchronous call, which cancelling the pull cancels.
 */
public final class GoogleSecretManagerSecretPipelineWriterImpl extends SecretPipelineWriterBase {
    /** The longest ID Secret Manager accepts for a secret. */
    public static final int MAX_SECRET_NAME_LENGTH = 255;

    private final SecretManagerServiceClient client;
    private final boolean ownsClient;
    private final String projectId;

    /**
     * A writer reading secrets through a new client, made from {@code settings} with the
     * ReceiveBufferScrubber added to its channel, which {@link #close} closes.
     *
     * @param settings    the client's settings - credentials, endpoint, retries - e.g. from
     *                    {@link SecretManagerServiceSettings#newBuilder()}. Its transport must be gRPC
     *                    (an {@link InstantiatingGrpcChannelProvider}, the default): the scrubber is
     *                    added through the provider's channel configurator, after any configurator
     *                    and interceptor provider already set, which are kept.
     * @param projectId   the project whose secrets are read: its ID or number
     * @param protector   encrypts every value read. Owned by the caller: the writer never closes it.
     * @param secretNames the secrets to pull, each a secret ID with the key to read after '#' if any.
     *                    Copied: a later change to the list isn't seen.
     * @throws NullPointerException     settings, projectId, protector or secretNames is null
     * @throws IllegalArgumentException projectId is empty, or holds anything but ASCII letters,
     *                                  digits, hyphens, dots and colons; or secretNames is empty, or
     *                                  holds a null, an ID Secret Manager can't hold (with a key), one
     *                                  whose file name isn't one FilePerSecretCacheImpl can read, or
     *                                  two with the same file name, in any case; or the settings'
     *                                  transport isn't an InstantiatingGrpcChannelProvider
     * @throws IOException              the client could not be created, e.g. no credentials were found
     */
    public GoogleSecretManagerSecretPipelineWriterImpl(SecretManagerServiceSettings settings, String projectId, PipelineDataProtector protector,
            List<String> secretNames) throws IOException {
        super(protector, secretNames, GoogleSecretManagerSecretPipelineWriterImpl::isValidSecretName);
        Objects.requireNonNull(settings, "settings");
        this.projectId = checkProjectId(projectId);
        this.client = SecretManagerServiceClient.create(withScrubber(settings));
        this.ownsClient = true;
    }

    /** A writer over a client the caller built, and closes: the tests', with the ReceiveBufferScrubber already on its channel. */
    GoogleSecretManagerSecretPipelineWriterImpl(SecretManagerServiceClient client, String projectId, PipelineDataProtector protector,
            List<String> secretNames) {
        super(protector, secretNames, GoogleSecretManagerSecretPipelineWriterImpl::isValidSecretName);
        this.client = Objects.requireNonNull(client, "client");
        this.projectId = checkProjectId(projectId);
        this.ownsClient = false;
    }

    /**
     * A writer reading secrets through a new client with the default settings - the global endpoint,
     * over gRPC, signed in with Application Default Credentials (Workload Identity on GKE) - which
     * {@link #close} closes.
     *
     * @param projectId   the project whose secrets are read: its ID or number
     * @param protector   encrypts every value read. Owned by the caller: the writer never closes it.
     * @param secretNames the secrets to pull, as for the constructor
     * @throws NullPointerException     projectId, protector or secretNames is null
     * @throws IllegalArgumentException as for the constructor
     * @throws IOException              the client could not be created, e.g. no credentials were found
     */
    public static GoogleSecretManagerSecretPipelineWriterImpl create(String projectId, PipelineDataProtector protector, List<String> secretNames)
            throws IOException {
        return new GoogleSecretManagerSecretPipelineWriterImpl(SecretManagerServiceSettings.newBuilder().build(), projectId, protector, secretNames);
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

    /** Closes the client this writer created; a client passed in is left open. */
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

    /**
     * {@inheritDoc}
     *
     * @throws ApiException               any Secret Manager failure but NOT_FOUND
     * @throws CryptographicException     the payload doesn't match its CRC32C, or the response names a
     *                                    different secret
     * @throws InvalidSecretDataException the payload isn't UTF-8 text, or a JSON object payload holds
     *                                    a key twice
     */
    @Override
    protected void readSecret(String name, List<SecretRequest> requests, Map<String, String> values) {
        AccessSecretVersionResponse response;
        try {
            response = client.accessSecretVersion(request(name));
        } catch (ApiException e) {
            if (isNotFound(e))
                return; // missing: nothing handed over
            throw e;
        }

        accept(response, name, requests, values);
    }

    @Override
    protected CompletableFuture<Void> readSecretAsync(String name, List<SecretRequest> requests, Map<String, String> values) {
        ApiFuture<AccessSecretVersionResponse> call;
        try {
            call = Objects.requireNonNull(client.accessSecretVersionCallable().futureCall(request(name)),
                    "The Secret Manager client returned no future.");
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }

        var read = new CompletableFuture<Void>();
        ApiFutures.addCallback(call, new ApiFutureCallback<>() {
            @Override
            public void onSuccess(AccessSecretVersionResponse response) {
                // Cancelled while the answer was on its way: nothing would be kept anyway.
                if (read.isDone()) {
                    scrub(response.getPayload().getData());
                    return;
                }
                try {
                    accept(response, name, requests, values);
                    read.complete(null);
                } catch (RuntimeException | Error e) {
                    read.completeExceptionally(e);
                }
            }

            @Override
            public void onFailure(Throwable error) {
                if (isNotFound(KeyWrapperFutures.unwrap(error)))
                    read.complete(null); // missing: nothing handed over
                else
                    read.completeExceptionally(error);
            }
        }, Runnable::run);
        read.whenComplete((ignored, error) -> {
            if (read.isCancelled())
                call.cancel(true);
        });
        return read;
    }

    // The settings with the scrubber added to every channel their provider builds, as
    // hkdfguard-cache-googlesecretmanager adds it: through the channel configurator, which gax
    // applies after the interceptor provider's interceptors - leaving those, and any configurator
    // already set, as they were.
    private static SecretManagerServiceSettings withScrubber(SecretManagerServiceSettings settings) throws IOException {
        if (!(settings.getTransportChannelProvider() instanceof InstantiatingGrpcChannelProvider provider))
            throw new IllegalArgumentException("The settings' transport must be gRPC, through an InstantiatingGrpcChannelProvider, so the "
                    + "writer can zero the buffer each response is parsed from; got "
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

    // Checks the response, encrypts its payload into values, and zeroes the payload either way.
    private void accept(AccessSecretVersionResponse response, String name, List<SecretRequest> requests, Map<String, String> values) {
        var payload = response.getPayload().getData();
        try {
            checkResponse(response, name, payload);
            if (payload.isEmpty())
                return;

            // The ByteString's own array when it is exactly the payload - as parsing makes it - else
            // an exact copy; zeroed either way.
            var bytes = exactBytes(payload);
            try {
                protectSecret(bytes, bytes.length, requests, values);
            } finally {
                ArrayUtility.zeroMemory(bytes);
            }
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
