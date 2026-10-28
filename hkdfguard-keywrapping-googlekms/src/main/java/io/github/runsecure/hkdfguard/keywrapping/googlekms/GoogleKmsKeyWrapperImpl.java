package io.github.runsecure.hkdfguard.keywrapping.googlekms;

import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutureCallback;
import com.google.api.core.ApiFutures;
import com.google.api.gax.rpc.ApiException;
import com.google.cloud.kms.v1.CryptoKeyName;
import com.google.cloud.kms.v1.DecryptRequest;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.EncryptRequest;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteOutput;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import com.google.protobuf.UnsafeByteOperations;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.abstractions.LocalKeyGeneration;
import io.github.runsecure.hkdfguard.abstractions.Utf8Utility;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import io.github.runsecure.hkdfguard.securefile.TrustedKeyFile;
import io.grpc.StatusRuntimeException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.zip.CRC32C;

/**
 * Protects (Encrypt) and reveals (Decrypt) a DEK under one symmetric Google Cloud KMS key (purpose
 * ENCRYPT_DECRYPT). The KEK never enters this process; every call is a network round trip,
 * authorized by the caller's Google credential through IAM and recorded in Cloud Audit Logs.
 * <p>
 * The key is pinned: Decrypt is always called against the key given at construction, and Cloud KMS
 * refuses a ciphertext made under any other key, so a substituted key file wrapped under another key
 * this principal may use is never revealed. A ciphertext names the key version that made it, so
 * Cloud KMS's own key rotation is transparent here - each key file keeps decrypting under its
 * version, which must stay enabled while the file is in use.
 * <p>
 * Every wrapped DEK is bound, as additional authenticated data, to a fixed HkdfGuard label and the
 * optional context: Decrypt fails unless both are presented again exactly. The label stops a
 * ciphertext the same key made for some other purpose being accepted as a DEK; the context stops a
 * key file made for one application being used by another that shares the key. Neither is secret.
 * Wrapped DEKs are byte for byte the .NET {@code GoogleKmsKeyWrapper}'s: a key file made by either
 * is read by the other, given the same key and context.
 * <p>
 * Symmetric encryption needs no secret beyond permission to use the key, so anyone allowed
 * {@code cloudkms.cryptoKeyVersions.useToEncrypt} can make a key file this wrapper accepts. Give the
 * application decrypt only (roles/cloudkms.cryptoKeyDecrypter) and the pipeline that creates key
 * files encrypt only; and key files are read only from where an untrusted account can't have
 * written or replaced them (see {@link #readKeyFileAsync} and {@link KeyFileTrust}).
 * <p>
 * Every request and response carries a CRC32C checksum, as Google recommends, so data corrupted in
 * transit is refused rather than stored or used. Cloud KMS has no "generate data key", so
 * {@link #generateAndWrapAsync} generates the DEK in this process, wraps it, and zeroes it.
 * Plaintext key bytes this class can reach are zeroed once used: its copy of the key sent to
 * Encrypt (wrapped into the request without a copy, and zeroed only once the call has completed,
 * since the client may send it again on a retry), and the array inside the {@link ByteString}
 * Decrypt returns (reached through {@link UnsafeByteOperations#unsafeWriteTo}, which hands over the
 * array itself). gRPC's serialized request and response aren't exposed, so they can't be, and live
 * until collected.
 * <p>
 * The {@link KeyManagementServiceClient} is the application's: it creates the client (credentials,
 * endpoint, retry settings), keeps it open for as long as anything uses this wrapper - a key ring's
 * background refresh included - and closes it. This wrapper never closes it. Each method returns as
 * soon as the request is sent; the future completes on the client's threads. Argument errors throw
 * from the call itself; everything else - a Cloud KMS refusal, an unreachable Cloud KMS, a revealed
 * key that doesn't fit - completes the future exceptionally. Cancelling a returned future cancels
 * the Cloud KMS request.
 */
public final class GoogleKmsKeyWrapperImpl implements KeyWrapper {
    /** The length of the DEK {@link #generateAndWrapAsync} generates: 32 bytes (AES-256). */
    public static final int GENERATED_KEY_LENGTH = 32;

    /** The largest plaintext Cloud KMS's Encrypt accepts, in bytes. */
    public static final int MAX_PLAINTEXT_LENGTH = 64 * 1024;

    /**
     * The longest context, in UTF-8 bytes: what Cloud KMS's additional authenticated data allows,
     * less the HkdfGuard label.
     */
    public static final int MAX_CONTEXT_LENGTH = 64 * 1024 - 32;

    // Prefixed to every wrapped DEK's additional authenticated data. Changing it makes every
    // existing key file unreadable.
    private static final byte[] AAD_LABEL = "HkdfGuard-GoogleKms-wrap-v1\0".getBytes(StandardCharsets.US_ASCII);


    private final KeyManagementServiceClient client;
    private final String keyName;
    private final ByteString aad;
    private final long aadCrc32c;
    private final KeyFileTrust keyFileTrust;

    /**
     * A wrapper binding no context, reading key files only administrators can have written
     * ({@link KeyFileTrust#ADMINISTRATORS_ONLY}).
     *
     * @param client  the Cloud KMS client every call is made through; see {@link #GoogleKmsKeyWrapperImpl(KeyManagementServiceClient, String, String, KeyFileTrust)}
     * @param keyName the symmetric key that wraps every DEK, as its resource name; see {@link #GoogleKmsKeyWrapperImpl(KeyManagementServiceClient, String, String, KeyFileTrust)}
     * @throws NullPointerException     client or keyName is null
     * @throws IllegalArgumentException keyName isn't a Cloud KMS key's resource name
     */
    public GoogleKmsKeyWrapperImpl(KeyManagementServiceClient client, String keyName) {
        this(client, keyName, null, null);
    }

    /**
     * A wrapper reading key files only administrators can have written
     * ({@link KeyFileTrust#ADMINISTRATORS_ONLY}).
     *
     * @param client  the Cloud KMS client every call is made through; see {@link #GoogleKmsKeyWrapperImpl(KeyManagementServiceClient, String, String, KeyFileTrust)}
     * @param keyName the symmetric key that wraps every DEK, as its resource name; see {@link #GoogleKmsKeyWrapperImpl(KeyManagementServiceClient, String, String, KeyFileTrust)}
     * @param context bound into every wrapped DEK and required again to reveal it; null or empty
     *                binds none. Not secret.
     * @throws NullPointerException     client or keyName is null
     * @throws IllegalArgumentException keyName isn't a Cloud KMS key's resource name, or the context
     *                                  holds an unpaired surrogate or is over {@link #MAX_CONTEXT_LENGTH} bytes
     */
    public GoogleKmsKeyWrapperImpl(KeyManagementServiceClient client, String keyName, String context) {
        this(client, keyName, context, null);
    }

    /**
     * A wrapper over one Cloud KMS key, binding {@code context} into every wrapped DEK and trusting
     * {@code keyFileTrust}, besides the administrators, to have written its key files.
     *
     * @param client       the Cloud KMS client every call is made through, e.g. from
     *                     {@link KeyManagementServiceClient#create()}. Not closed by this wrapper;
     *                     its owner (typically the application, or its dependency injection
     *                     container) closes it.
     * @param keyName      the symmetric key that wraps every DEK, as its resource name:
     *                     projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}.
     *                     Not a key version: Decrypt takes the key, and Encrypt uses its primary
     *                     version.
     * @param context      bound into every wrapped DEK and required again to reveal it; null or empty
     *                     binds none. Not secret.
     * @param keyFileTrust who besides the operating system's administrators may have written a key
     *                     file {@link #readKeyFileAsync} reads; null trusts administrators only
     *                     ({@link KeyFileTrust#ADMINISTRATORS_ONLY})
     * @throws NullPointerException     client or keyName is null
     * @throws IllegalArgumentException keyName isn't a Cloud KMS key's resource name, or the context
     *                                  holds an unpaired surrogate or is over {@link #MAX_CONTEXT_LENGTH} bytes
     */
    public GoogleKmsKeyWrapperImpl(KeyManagementServiceClient client, String keyName, String context, KeyFileTrust keyFileTrust) {
        this.client = Objects.requireNonNull(client, "client");
        Objects.requireNonNull(keyName, "keyName");
        if (!isKeyName(keyName))
            throw new IllegalArgumentException("'" + keyName + "' isn't a Cloud KMS key's resource name: "
                    + "projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}, without a key version.");

        var contextBytes = encodeContext(context);
        if (contextBytes.length > MAX_CONTEXT_LENGTH)
            throw new IllegalArgumentException("The context is " + contextBytes.length + " bytes in UTF-8; at most "
                    + MAX_CONTEXT_LENGTH + " are allowed.");

        var aadBytes = Arrays.copyOf(AAD_LABEL, AAD_LABEL.length + contextBytes.length);
        System.arraycopy(contextBytes, 0, aadBytes, AAD_LABEL.length, contextBytes.length);

        this.keyName = keyName;
        this.aad = ByteString.copyFrom(aadBytes);
        this.aadCrc32c = crc32c(aadBytes);
        this.keyFileTrust = keyFileTrust != null ? keyFileTrust : KeyFileTrust.ADMINISTRATORS_ONLY;
    }

    /**
     * {@inheritDoc}
     *
     * @return completes with the number of bytes written to result; fails with a
     *         {@link CryptographicException} when Cloud KMS refused the request or could not be
     *         reached (the client's {@link ApiException} is the cause), the request or response was
     *         corrupted in transit, or the wrapped DEK is over {@link WrappedKeyLimits#MAX_BYTES}, or
     *         with an {@link IllegalArgumentException} when result is too small for the wrapped DEK
     * @throws NullPointerException     plaintext or result is null
     * @throws IllegalArgumentException plaintext is empty or over {@link #MAX_PLAINTEXT_LENGTH} bytes
     */
    @Override
    public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(result, "result");
        if (plaintext.length == 0 || plaintext.length > MAX_PLAINTEXT_LENGTH)
            throw new IllegalArgumentException("Cloud KMS wraps 1-" + MAX_PLAINTEXT_LENGTH + " bytes; got " + plaintext.length + ".");

        // Wrapped rather than copied into the request, so zeroing it reaches the bytes the request
        // holds; zeroed only once the call has completed, since the client may send the request
        // again on a retry.
        var buffer = plaintext.clone();
        var request = EncryptRequest.newBuilder()
                .setName(keyName)
                .setPlaintext(UnsafeByteOperations.unsafeWrap(buffer))
                .setPlaintextCrc32C(Int64Value.of(crc32c(buffer)))
                .setAdditionalAuthenticatedData(aad)
                .setAdditionalAuthenticatedDataCrc32C(Int64Value.of(aadCrc32c))
                .build();

        var call = send(() -> client.encryptCallable().futureCall(request));
        var completed = call.whenComplete((response, error) -> ArrayUtility.zeroMemory(buffer));
        return KeyWrapperFutures.cancelling(completed.handle((response, error) -> {
            if (error != null)
                throw translate(error, "wrap");
            return copyWrapped(response, result);
        }), call);
    }

    /**
     * {@inheritDoc}
     *
     * @return completes with the number of bytes written to result; fails with a
     *         {@link CryptographicException} when wrapped is empty or over
     *         {@link WrappedKeyLimits#MAX_BYTES}, or Cloud KMS refused it - tampered with, wrapped
     *         under another key, or under a different context - or could not be reached (the
     *         client's {@link ApiException} is the cause), or the response was corrupted in transit,
     *         or with an {@link IllegalArgumentException} when result is too small for the revealed
     *         key. On any failure after Cloud KMS is called, result is zeroed.
     * @throws NullPointerException wrapped or result is null
     */
    @Override
    public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
        Objects.requireNonNull(wrapped, "wrapped");
        Objects.requireNonNull(result, "result");
        // Refused locally: no ciphertext this wrapper produced is outside these bounds.
        if (wrapped.length == 0 || wrapped.length > WrappedKeyLimits.MAX_BYTES)
            return CompletableFuture.failedFuture(new CryptographicException(
                    "A wrapped DEK is 1-" + WrappedKeyLimits.MAX_BYTES + " bytes; got " + wrapped.length + "."));

        var request = DecryptRequest.newBuilder()
                .setName(keyName)
                .setCiphertext(ByteString.copyFrom(wrapped))
                .setCiphertextCrc32C(Int64Value.of(crc32c(wrapped)))
                .setAdditionalAuthenticatedData(aad)
                .setAdditionalAuthenticatedDataCrc32C(Int64Value.of(aadCrc32c))
                .build();

        var call = send(() -> client.decryptCallable().futureCall(request));
        return KeyWrapperFutures.cancelling(call.handle((response, error) -> {
            try {
                if (error != null)
                    throw translate(error, "unwrap");
                return copyRevealed(response, result);
            } catch (RuntimeException | Error e) {
                ArrayUtility.zeroMemory(result);
                throw e;
            }
        }), call);
    }

    /**
     * Generates a fresh {@link #GENERATED_KEY_LENGTH}-byte DEK in this process, wraps it, and zeroes
     * it - it is never returned. Cloud KMS has no "generate data key".
     *
     * @param result the wrapped key
     * @return as {@link #wrapAsync}
     * @throws NullPointerException result is null
     */
    @Override
    public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
        // wrapAsync copies the DEK before it returns, so it can be zeroed straight away.
        return LocalKeyGeneration.generateAndWrap(this, GENERATED_KEY_LENGTH, result);
    }

    /**
     * Reads a key file this wrapper wrote, still wrapped, refusing one that an account other than
     * the operating system's administrators and the {@link KeyFileTrust} given at construction could
     * have written or replaced - the Java equivalent of the native library's checks
     * ({@link TrustedKeyFile}). On Windows the file must be on a local fixed drive, reached through
     * real folders (no symbolic link, junction or substituted drive), and it and every folder above
     * it must be owned by, and modifiable only by, trusted principals. On Linux and macOS it and
     * every directory above it must be owned by root or a trusted user and writable by nobody else
     * (by its group only if that group is trusted), and only symbolic links a trusted user owns are
     * followed. It is also refused if it is empty, over {@link WrappedKeyLimits#MAX_BYTES}, or looks
     * like an unwrapped key. The file is read on the calling thread; no Cloud KMS call is made.
     *
     * @param path the key file's path
     * @return completes with the file's contents, still wrapped; fails with a
     *         {@link java.nio.file.NoSuchFileException} (the file doesn't exist), a
     *         {@link java.nio.file.AccessDeniedException} (this account may not read the file, or it
     *         isn't somewhere only trusted principals can modify), an
     *         {@link io.github.runsecure.hkdfguard.abstractions.InvalidKeyFileException} (the file is
     *         empty, too long, or holds what looks like an unwrapped key), another
     *         {@link java.io.IOException} (the file can't be read, or another process has it open
     *         for writing), or an {@link IllegalArgumentException} (the {@link KeyFileTrust} names a
     *         principal that can't be trusted)
     * @throws NullPointerException path is null
     */
    @Override
    public CompletableFuture<byte[]> readKeyFileAsync(Path path) {
        return TrustedKeyFile.readAsync(path, keyFileTrust);
    }

    /** CRC32C (Castagnoli), as Cloud KMS checksums requests and responses. */
    static long crc32c(byte[] data) {
        var crc = new CRC32C();
        crc.update(data);
        return crc.getValue();
    }

    /** CRC32C of a ByteString's bytes, read in place. */
    static long crc32c(ByteString data) {
        var crc = new CRC32C();
        crc.update(data.asReadOnlyByteBuffer());
        return crc.getValue();
    }

    /**
     * Zeroes the bytes a ByteString holds. ByteString is immutable to callers, but
     * {@link UnsafeByteOperations#unsafeWriteTo} hands its own arrays to a {@link ByteOutput}, and
     * nothing else holds the one a response was parsed into.
     */
    static void scrub(ByteString bytes) {
        try {
            UnsafeByteOperations.unsafeWriteTo(bytes, ZEROING);
        } catch (IOException e) {
            throw new UncheckedIOException(e); // ZEROING never throws
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
                return; // out of reach, like gRPC's own copies (see the class comment)
            while (value.hasRemaining())
                value.put((byte) 0);
        }
    };

    // Only the canonical form, every part named: a full resource name ("//cloudkms.googleapis.com/...")
    // or one with a trailing slash would be sent as it is, and could never match the version Encrypt
    // reports; the client's own parser accepts an empty part, which no key has.
    private static boolean isKeyName(String keyName) {
        if (!CryptoKeyName.isParsableFrom(keyName))
            return false;
        var parsed = CryptoKeyName.parse(keyName);
        return parsed.toString().equals(keyName)
                && !parsed.getProject().isEmpty() && !parsed.getLocation().isEmpty()
                && !parsed.getKeyRing().isEmpty() && !parsed.getCryptoKey().isEmpty();
    }

    // Strict UTF-8, as .NET and the other ports encode the context: an unpaired surrogate would
    // otherwise be replaced, binding a context that differs from the one the caller gave.
    private static byte[] encodeContext(String context) {
        if (context == null)
            return new byte[0];
        try {
            return Utf8Utility.encodeStrict(context);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The context isn't well-formed text: it holds an unpaired surrogate.", e);
        }
    }

    // The client's future as a CompletableFuture, or a failed one if the call threw instead of
    // returning one. Cancelling it cancels the client's future, and with it the gRPC call.
    private static <T> CompletableFuture<T> send(Supplier<ApiFuture<T>> call) {
        ApiFuture<T> sent;
        try {
            sent = Objects.requireNonNull(call.get(), "The Cloud KMS client returned no future.");
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }

        var future = new CompletableFuture<T>();
        ApiFutures.addCallback(sent, new ApiFutureCallback<T>() {
            @Override
            public void onSuccess(T value) {
                future.complete(value);
            }

            @Override
            public void onFailure(Throwable error) {
                future.completeExceptionally(error);
            }
        }, Runnable::run);
        future.whenComplete((value, error) -> {
            if (future.isCancelled())
                sent.cancel(true);
        });
        return future;
    }

    // Turns Cloud KMS failures - service refusals and transport failures (ApiException, naming the
    // gRPC status), and client-side ones - into the CryptographicException every KeyWrapper fails
    // with. Cancellation is left as it is. A CANCELLED status the caller didn't ask for is a failure.
    private RuntimeException translate(Throwable error, String operation) {
        error = KeyWrapperFutures.unwrap(error);
        if (error instanceof CancellationException e)
            return e;
        if (error instanceof CryptographicException e)
            return e;
        if (error instanceof Error e)
            throw e;
        if (error instanceof ApiException e)
            return new CryptographicException("Cloud KMS " + operation + " failed for key '" + keyName + "': "
                    + e.getStatusCode().getCode() + ": " + detail(e), e);
        return new CryptographicException("Cloud KMS " + operation + " failed for key '" + keyName + "': " + error.getMessage(), error);
    }

    // Google's own description of the failure: the gRPC status's, rather than the exception's
    // message, which repeats the exception class and status code.
    private static String detail(ApiException e) {
        if (e.getCause() instanceof StatusRuntimeException s && s.getStatus().getDescription() != null)
            return s.getStatus().getDescription();
        return e.getMessage();
    }

    private int copyWrapped(EncryptResponse response, byte[] result) {
        // The version that made it must be one of this key's: a response for any other key would
        // produce a key file this wrapper can't read back.
        var prefix = keyName + "/cryptoKeyVersions/";
        var name = response.getName();
        var version = name.startsWith(prefix) ? name.substring(prefix.length()) : "";
        if (version.isEmpty() || version.indexOf('/') >= 0)
            throw new CryptographicException("Cloud KMS wrap for key '" + keyName + "' reported key version '" + name + "' instead.");

        if (!response.getVerifiedPlaintextCrc32C() || !response.getVerifiedAdditionalAuthenticatedDataCrc32C())
            throw new CryptographicException("Cloud KMS wrap for key '" + keyName
                    + "' didn't verify the request's checksums: it was corrupted in transit.");

        var ciphertext = response.getCiphertext();
        if (ciphertext.isEmpty())
            throw new CryptographicException("Cloud KMS wrap for key '" + keyName + "' returned no ciphertext.");
        if (!response.hasCiphertextCrc32C() || response.getCiphertextCrc32C().getValue() != crc32c(ciphertext))
            throw new CryptographicException("Cloud KMS wrap for key '" + keyName
                    + "' returned a ciphertext that doesn't match its checksum: it was corrupted in transit.");

        // A key file over the limit would be refused when read back, so refuse to produce one.
        if (ciphertext.size() > WrappedKeyLimits.MAX_BYTES)
            throw new CryptographicException("Cloud KMS wrap for key '" + keyName + "' returned " + ciphertext.size()
                    + " bytes; a wrapped DEK is at most " + WrappedKeyLimits.MAX_BYTES + ".");
        if (ciphertext.size() > result.length)
            throw new IllegalArgumentException("The wrapped DEK is " + ciphertext.size() + " bytes; result holds " + result.length + ".");

        ciphertext.copyTo(result, 0);
        return ciphertext.size();
    }

    private int copyRevealed(DecryptResponse response, byte[] result) {
        var revealed = response.getPlaintext();
        try {
            if (revealed.isEmpty())
                throw new CryptographicException("Cloud KMS unwrap for key '" + keyName + "' returned no plaintext.");
            if (!response.hasPlaintextCrc32C() || response.getPlaintextCrc32C().getValue() != crc32c(revealed))
                throw new CryptographicException("Cloud KMS unwrap for key '" + keyName
                        + "' returned a plaintext that doesn't match its checksum: it was corrupted in transit.");
            if (revealed.size() > result.length)
                throw new IllegalArgumentException("The revealed key is " + revealed.size() + " bytes; result holds " + result.length + ".");

            revealed.copyTo(result, 0);
            return revealed.size();
        } finally {
            scrub(revealed);
        }
    }
}
