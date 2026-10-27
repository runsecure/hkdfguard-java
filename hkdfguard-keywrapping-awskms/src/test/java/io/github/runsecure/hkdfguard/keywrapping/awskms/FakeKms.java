package io.github.runsecure.hkdfguard.keywrapping.awskms;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyWithoutPlaintextRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyWithoutPlaintextResponse;
import software.amazon.awssdk.services.kms.model.InvalidCiphertextException;

/**
 * An in-process stand-in for KMS, implementing only the three calls AwsKmsKeyWrapperImpl makes:
 * every other KmsAsyncClient operation keeps the SDK's default, which throws
 * UnsupportedOperationException. By default it behaves like a symmetric KMS key: ciphertext is
 * AES-GCM under a local key, binding the key ID and encryption context, so Decrypt fails unless both
 * match. Each call can be replaced with a handler to return or throw what a test needs. Every
 * request is recorded; Encrypt's plaintext is copied when the request is read, since the wrapper
 * zeroes it afterwards.
 * <p>
 * Each call completes its future before returning, unless {@link #deferred} is set: then the
 * request is read and answered on another thread a little later, as a real client would, after the
 * call has returned.
 */
class FakeKms implements KmsAsyncClient {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] key = new byte[32];

    Function<EncryptRequest, EncryptResponse> onEncrypt;
    Function<DecryptRequest, DecryptResponse> onDecrypt;
    Function<GenerateDataKeyWithoutPlaintextRequest, GenerateDataKeyWithoutPlaintextResponse> onGenerate;

    /** Answer each call on another thread, after it has returned. */
    boolean deferred;

    final List<EncryptRequest> encryptRequests = new CopyOnWriteArrayList<>();
    final List<byte[]> encryptPlaintexts = new CopyOnWriteArrayList<>();
    final List<DecryptRequest> decryptRequests = new CopyOnWriteArrayList<>();
    final List<GenerateDataKeyWithoutPlaintextRequest> generateRequests = new CopyOnWriteArrayList<>();

    /** The plaintext of every Decrypt response returned, to check it was zeroed. */
    final List<SdkBytes> decryptPlaintexts = new CopyOnWriteArrayList<>();

    /** Every future a call returned, to check a cancellation reached it. */
    final List<CompletableFuture<?>> futures = new CopyOnWriteArrayList<>();

    FakeKms() {
        RANDOM.nextBytes(key);
    }

    @Override
    public String serviceName() {
        return SERVICE_NAME;
    }

    @Override
    public void close() {
    }

    @Override
    public CompletableFuture<EncryptResponse> encrypt(EncryptRequest request) {
        return answer(() -> {
            encryptRequests.add(request);
            encryptPlaintexts.add(request.plaintext().asByteArray());
            if (onEncrypt != null)
                return onEncrypt.apply(request);
            return EncryptResponse.builder()
                    .keyId(request.keyId())
                    .ciphertextBlob(SdkBytes.fromByteArray(seal(request.plaintext().asByteArray(), request.keyId(), request.encryptionContext())))
                    .build();
        });
    }

    @Override
    public CompletableFuture<DecryptResponse> decrypt(DecryptRequest request) {
        return answer(() -> {
            decryptRequests.add(request);
            var response = onDecrypt != null
                    ? onDecrypt.apply(request)
                    : DecryptResponse.builder()
                            .keyId(request.keyId())
                            // Built the way the SDK's unmarshaller builds it: a copy of the decoded array.
                            .plaintext(SdkBytes.fromByteArray(open(request.ciphertextBlob().asByteArray(), request.keyId(), request.encryptionContext())))
                            .build();
            if (response.plaintext() != null)
                decryptPlaintexts.add(response.plaintext());
            return response;
        });
    }

    @Override
    public CompletableFuture<GenerateDataKeyWithoutPlaintextResponse> generateDataKeyWithoutPlaintext(GenerateDataKeyWithoutPlaintextRequest request) {
        return answer(() -> {
            generateRequests.add(request);
            if (onGenerate != null)
                return onGenerate.apply(request);
            var dek = new byte[32];
            RANDOM.nextBytes(dek);
            return GenerateDataKeyWithoutPlaintextResponse.builder()
                    .keyId(request.keyId())
                    .ciphertextBlob(SdkBytes.fromByteArray(seal(dek, request.keyId(), request.encryptionContext())))
                    .build();
        });
    }

    private <T> CompletableFuture<T> answer(Supplier<T> work) {
        CompletableFuture<T> future;
        if (deferred) {
            future = CompletableFuture.supplyAsync(work, CompletableFuture.delayedExecutor(50, TimeUnit.MILLISECONDS));
        } else {
            try {
                future = CompletableFuture.completedFuture(work.get());
            } catch (RuntimeException e) {
                future = CompletableFuture.failedFuture(e);
            }
        }
        futures.add(future);
        return future;
    }

    private byte[] seal(byte[] plaintext, String keyId, Map<String, String> context) {
        try {
            var sealed = new byte[12 + plaintext.length + 16];
            var nonce = new byte[12];
            RANDOM.nextBytes(nonce);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad(keyId, context));
            System.arraycopy(nonce, 0, sealed, 0, 12);
            cipher.doFinal(plaintext, 0, plaintext.length, sealed, 12);
            return sealed;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] open(byte[] sealed, String keyId, Map<String, String> context) {
        if (sealed.length < 28)
            throw invalidCiphertext();

        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, sealed, 0, 12));
            cipher.updateAAD(aad(keyId, context));
            return cipher.doFinal(sealed, 12, sealed.length - 12);
        } catch (AEADBadTagException e) {
            // Real KMS reports a key mismatch as IncorrectKeyException and a context mismatch or
            // tampering as InvalidCiphertextException; one is enough for a fake.
            throw invalidCiphertext();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** An exception shaped like the one the SDK raises for a KMS error response. */
    static <T extends AwsServiceException> T serviceError(AwsServiceException.Builder builder, String errorCode, int status) {
        @SuppressWarnings("unchecked")
        var error = (T) builder
                .message(errorCode + " from FakeKms.")
                .awsErrorDetails(AwsErrorDetails.builder().errorCode(errorCode).serviceName("KMS").build())
                .requestId("fake-request-id")
                .statusCode(status)
                .build();
        return error;
    }

    private static InvalidCiphertextException invalidCiphertext() {
        return serviceError(InvalidCiphertextException.builder(), "InvalidCiphertextException", 400);
    }

    private static byte[] aad(String keyId, Map<String, String> context) {
        var text = new StringBuilder(keyId);
        for (var entry : new TreeMap<>(context).entrySet())
            text.append('\0').append(entry.getKey()).append('=').append(entry.getValue());
        return text.toString().getBytes(StandardCharsets.UTF_8);
    }
}
