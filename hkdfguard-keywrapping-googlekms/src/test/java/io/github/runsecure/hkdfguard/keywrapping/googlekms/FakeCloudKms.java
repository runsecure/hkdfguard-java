package io.github.runsecure.hkdfguard.keywrapping.googlekms;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.cloud.kms.v1.DecryptRequest;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.EncryptRequest;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceGrpc;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.cloud.kms.v1.ProtectionLevel;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * An in-process stand-in for Cloud KMS: a gRPC server implementing only the two calls
 * GoogleKmsKeyWrapperImpl makes (any other answers UNIMPLEMENTED), reached through a real
 * {@link KeyManagementServiceClient}, so the client's own error mapping, retries and cancellation
 * run as they would against Cloud KMS. By default it behaves like a set of symmetric keys, each with
 * a primary version: ciphertext is AES-GCM under a local key, binding the key name, the version and
 * the additional authenticated data, so Decrypt fails unless all three match. It checks request
 * checksums and sets response ones as Cloud KMS does. Each call can be replaced with a handler to
 * return what a test needs, or throw a {@link StatusRuntimeException} for an error status. Every
 * request is recorded; Encrypt's plaintext is copied when it arrives, since the wrapper zeroes it
 * afterwards.
 * <p>
 * The in-process transport hands messages over without serializing them, so the request a handler
 * sees is the one the wrapper built, and the response the wrapper reads is the one returned here:
 * a test can check what the wrapper zeroed in either.
 */
final class FakeCloudKms implements AutoCloseable {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] key = new byte[32];
    private final Map<String, Integer> primaryVersions = new ConcurrentHashMap<>();
    private final Server server;
    private final ManagedChannel channel;
    private final KeyManagementServiceClient client;

    volatile Function<EncryptRequest, EncryptResponse> onEncrypt;
    volatile Function<DecryptRequest, DecryptResponse> onDecrypt;

    /** Never answer, until the client cancels the call. */
    volatile boolean hang;

    final List<EncryptRequest> encryptRequests = new CopyOnWriteArrayList<>();
    final List<byte[]> encryptPlaintexts = new CopyOnWriteArrayList<>();
    final List<DecryptRequest> decryptRequests = new CopyOnWriteArrayList<>();

    /** The plaintext of every Decrypt response returned, to check it was zeroed. */
    final List<ByteString> decryptPlaintexts = new CopyOnWriteArrayList<>();

    /** Counted down when the client cancels a call the fake is hanging on. */
    final CountDownLatch cancelled = new CountDownLatch(1);

    FakeCloudKms() {
        RANDOM.nextBytes(key);
        var name = InProcessServerBuilder.generateName();
        try {
            server = InProcessServerBuilder.forName(name).directExecutor().addService(new Service()).build().start();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        channel = InProcessChannelBuilder.forName(name).directExecutor().build();
        try {
            client = KeyManagementServiceClient.create(KeyManagementServiceSettings.newBuilder()
                    .setTransportChannelProvider(FixedTransportChannelProvider.create(GrpcTransportChannel.create(channel)))
                    .setCredentialsProvider(NoCredentialsProvider.create())
                    .build());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** A real Cloud KMS client, calling this fake. */
    KeyManagementServiceClient client() {
        return client;
    }

    /** Makes a new version of the key its primary, as rotating it in Cloud KMS does. */
    void rotate(String keyName) {
        primaryVersions.put(keyName, primaryVersion(keyName) + 1);
    }

    /** What the fake would answer to the request, before a test changes it. */
    EncryptResponse.Builder encryptNormally(EncryptRequest request) {
        return encrypt(request).toBuilder();
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

    /** The exception a handler throws for Cloud KMS to answer with an error status. */
    static StatusRuntimeException error(Status.Code code, String description) {
        return Status.fromCode(code).withDescription(description).asRuntimeException();
    }

    private final class Service extends KeyManagementServiceGrpc.KeyManagementServiceImplBase {
        @Override
        public void encrypt(EncryptRequest request, StreamObserver<EncryptResponse> responses) {
            answer(responses, () -> {
                encryptRequests.add(request);
                encryptPlaintexts.add(request.getPlaintext().toByteArray());
                var handler = onEncrypt;
                return handler != null ? handler.apply(request) : FakeCloudKms.this.encrypt(request);
            });
        }

        @Override
        public void decrypt(DecryptRequest request, StreamObserver<DecryptResponse> responses) {
            answer(responses, () -> {
                decryptRequests.add(request);
                var handler = onDecrypt;
                var response = handler != null ? handler.apply(request) : FakeCloudKms.this.decrypt(request);
                decryptPlaintexts.add(response.getPlaintext());
                return response;
            });
        }

        private <T> void answer(StreamObserver<T> responses, Supplier<T> work) {
            if (hang) {
                ((ServerCallStreamObserver<T>) responses).setOnCancelHandler(cancelled::countDown);
                return;
            }
            T response;
            try {
                response = work.get();
            } catch (StatusRuntimeException e) {
                responses.onError(e);
                return;
            }
            responses.onNext(response);
            responses.onCompleted();
        }
    }

    private EncryptResponse encrypt(EncryptRequest request) {
        checkCrc32c(request.getPlaintext(), request.hasPlaintextCrc32C() ? request.getPlaintextCrc32C() : null, "plaintext");
        checkCrc32c(request.getAdditionalAuthenticatedData(),
                request.hasAdditionalAuthenticatedDataCrc32C() ? request.getAdditionalAuthenticatedDataCrc32C() : null,
                "additional_authenticated_data");

        int version = primaryVersion(request.getName());
        var plaintext = request.getPlaintext().toByteArray();
        var nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        byte[] sealed;
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad(request.getName(), version, request.getAdditionalAuthenticatedData()));
            sealed = cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }

        // version (1) | nonce (12) | ciphertext and tag
        var ciphertext = new byte[1 + 12 + sealed.length];
        ciphertext[0] = (byte) version;
        System.arraycopy(nonce, 0, ciphertext, 1, 12);
        System.arraycopy(sealed, 0, ciphertext, 13, sealed.length);

        return EncryptResponse.newBuilder()
                .setName(request.getName() + "/cryptoKeyVersions/" + version)
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .setCiphertextCrc32C(Int64Value.of(GoogleKmsKeyWrapperImpl.crc32c(ciphertext)))
                .setVerifiedPlaintextCrc32C(request.hasPlaintextCrc32C())
                .setVerifiedAdditionalAuthenticatedDataCrc32C(request.hasAdditionalAuthenticatedDataCrc32C())
                .setProtectionLevel(ProtectionLevel.SOFTWARE)
                .build();
    }

    private DecryptResponse decrypt(DecryptRequest request) {
        checkCrc32c(request.getCiphertext(), request.hasCiphertextCrc32C() ? request.getCiphertextCrc32C() : null, "ciphertext");
        checkCrc32c(request.getAdditionalAuthenticatedData(),
                request.hasAdditionalAuthenticatedDataCrc32C() ? request.getAdditionalAuthenticatedDataCrc32C() : null,
                "additional_authenticated_data");

        var ciphertext = request.getCiphertext().toByteArray();
        if (ciphertext.length < 1 + 12 + 16)
            throw invalidCiphertext();

        byte[] plaintext;
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, ciphertext, 1, 12));
            cipher.updateAAD(aad(request.getName(), ciphertext[0], request.getAdditionalAuthenticatedData()));
            plaintext = cipher.doFinal(ciphertext, 13, ciphertext.length - 13);
        } catch (AEADBadTagException e) {
            // Cloud KMS gives the same answer for another key, another AAD, and tampering.
            throw invalidCiphertext();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }

        return DecryptResponse.newBuilder()
                .setPlaintext(ByteString.copyFrom(plaintext))
                .setPlaintextCrc32C(Int64Value.of(GoogleKmsKeyWrapperImpl.crc32c(plaintext)))
                .setUsedPrimary(ciphertext[0] == primaryVersion(request.getName()))
                .setProtectionLevel(ProtectionLevel.SOFTWARE)
                .build();
    }

    private int primaryVersion(String keyName) {
        return primaryVersions.getOrDefault(keyName, 1);
    }

    private static void checkCrc32c(ByteString data, Int64Value crc32c, String field) {
        if (crc32c != null && crc32c.getValue() != GoogleKmsKeyWrapperImpl.crc32c(data))
            throw error(Status.Code.INVALID_ARGUMENT, "The checksum in field " + field + "_crc32c did not match the data in field " + field + ".");
    }

    private static StatusRuntimeException invalidCiphertext() {
        return error(Status.Code.INVALID_ARGUMENT, "Decryption failed: the ciphertext is invalid.");
    }

    private static byte[] aad(String keyName, int version, ByteString aad) {
        var prefix = (keyName + "\0" + version + "\0").getBytes(StandardCharsets.UTF_8);
        var bytes = new byte[prefix.length + aad.size()];
        System.arraycopy(prefix, 0, bytes, 0, prefix.length);
        aad.copyTo(bytes, prefix.length);
        return bytes;
    }
}
