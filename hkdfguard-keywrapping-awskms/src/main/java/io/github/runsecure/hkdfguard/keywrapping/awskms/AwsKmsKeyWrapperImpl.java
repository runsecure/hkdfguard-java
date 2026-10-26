package io.github.runsecure.hkdfguard.keywrapping.awskms;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import io.github.runsecure.hkdfguard.securefile.TrustedKeyFile;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.AbortedException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyWithoutPlaintextRequest;

/**
 * Protects (Encrypt) and reveals (Decrypt) a DEK under one symmetric AWS KMS key, and generates
 * fresh DEKs with GenerateDataKeyWithoutPlaintext - so on that path the plaintext DEK never leaves
 * KMS. The KEK never enters this process; every call is a network round trip, authorized by the
 * caller's IAM credentials and recorded in CloudTrail.
 * <p>
 * The key is pinned on every Decrypt. A symmetric ciphertext blob names its own key and KMS would
 * otherwise decrypt it under whichever key it names, so a substituted key file wrapped under any
 * other key this principal may use would be revealed. With the key pinned KMS refuses it
 * (IncorrectKeyException). Prefer a key ARN to an alias: Decrypt resolves an alias when it is
 * called, so re-pointing the alias at a new key makes every DEK wrapped under the old one
 * unreadable. KMS's own automatic key rotation keeps the key ARN and is transparent here.
 * <p>
 * The encryption context, if any, is bound into every wrapped DEK as authenticated data: Decrypt
 * fails unless it is presented again exactly, and key policies can require it
 * ({@code kms:EncryptionContext:*}). It is logged in plaintext by CloudTrail, so it must not hold
 * secrets.
 * <p>
 * Key files are read only from where an untrusted account can't have written or replaced them (see
 * {@link #readKeyFileAsync} and {@link KeyFileTrust}). Pinning the key stops a key file wrapped
 * under another key; this stops one wrapped under this key by anyone who may call kms:Encrypt,
 * which would otherwise choose the DEK new data is encrypted under.
 * <p>
 * Plaintext key bytes this class can reach are zeroed once used: its copy of the key sent to
 * Encrypt, and the array inside the {@link SdkBytes} Decrypt returns (reached through
 * {@link SdkBytes#asByteArrayUnsafe()}, which hands over the array itself rather than a copy). The
 * AWS SDK base64-encodes the first into the JSON request body; it reads the second from the JSON
 * response body as base64 text, decodes that into an array of its own, and copies that array into
 * the SdkBytes. The request body, the response text and that decoded array aren't exposed, so they
 * can't be zeroed and live until collected.
 * <p>
 * The {@link KmsAsyncClient} is the application's: it builds the client (credentials, region, HTTP
 * client), keeps it open for as long as anything uses this wrapper - a key ring's background
 * refresh included - and closes it. This wrapper never closes it. Each method returns as soon as
 * the request is sent; the future completes on the SDK's completion executor. Argument errors
 * throw from the call itself; everything else - a KMS refusal, an unreachable KMS, a revealed key
 * that doesn't fit - completes the future exceptionally. Cancelling a returned future cancels the
 * KMS request.
 */
public final class AwsKmsKeyWrapperImpl implements KeyWrapper {
    /** The length of the DEK {@link #generateAndWrapAsync} generates: 32 bytes (AES-256). */
    public static final int GENERATED_KEY_LENGTH = 32;

    /** The largest plaintext KMS's Encrypt accepts, in bytes. */
    public static final int MAX_PLAINTEXT_LENGTH = 4096;

    private final KmsAsyncClient client;
    private final String keyId;
    private final Map<String, String> encryptionContext;
    private final KeyFileTrust keyFileTrust;

    /**
     * A wrapper binding no encryption context, reading key files only administrators can have
     * written ({@link KeyFileTrust#ADMINISTRATORS_ONLY}).
     *
     * @param client the KMS client every call is made through; see {@link #AwsKmsKeyWrapperImpl(KmsAsyncClient, String, Map, KeyFileTrust)}
     * @param keyId  the symmetric KMS key that wraps every DEK: a key ARN (preferred), key ID,
     *               alias name ("alias/...") or alias ARN
     * @throws NullPointerException     client or keyId is null
     * @throws IllegalArgumentException keyId is empty or whitespace
     */
    public AwsKmsKeyWrapperImpl(KmsAsyncClient client, String keyId) {
        this(client, keyId, null, null);
    }

    /**
     * A wrapper reading key files only administrators can have written
     * ({@link KeyFileTrust#ADMINISTRATORS_ONLY}).
     *
     * @param client            the KMS client every call is made through; see {@link #AwsKmsKeyWrapperImpl(KmsAsyncClient, String, Map, KeyFileTrust)}
     * @param keyId             the symmetric KMS key that wraps every DEK: a key ARN (preferred),
     *                          key ID, alias name ("alias/...") or alias ARN
     * @param encryptionContext bound into every wrapped DEK and required again to reveal it. Copied
     *                          at construction; null or empty binds none.
     * @throws NullPointerException     client or keyId is null, or the context holds a null value
     * @throws IllegalArgumentException keyId is empty or whitespace, or the context holds an empty or null key
     */
    public AwsKmsKeyWrapperImpl(KmsAsyncClient client, String keyId, Map<String, String> encryptionContext) {
        this(client, keyId, encryptionContext, null);
    }

    /**
     * A wrapper over one KMS key, binding {@code encryptionContext} into every wrapped DEK and
     * trusting {@code keyFileTrust}, besides the administrators, to have written its key files.
     *
     * @param client            the KMS client every call is made through. Not closed by this
     *                          wrapper; its owner (typically the application, or its dependency
     *                          injection container) closes it.
     * @param keyId             the symmetric KMS key that wraps every DEK: a key ARN (preferred),
     *                          key ID, alias name ("alias/...") or alias ARN
     * @param encryptionContext bound into every wrapped DEK and required again to reveal it. Copied
     *                          at construction; null or empty binds none.
     * @param keyFileTrust      who besides the operating system's administrators may have written a
     *                          key file {@link #readKeyFileAsync} reads; null trusts administrators
     *                          only ({@link KeyFileTrust#ADMINISTRATORS_ONLY})
     * @throws NullPointerException     client or keyId is null, or the context holds a null value
     * @throws IllegalArgumentException keyId is empty or whitespace, or the context holds an empty or null key
     */
    public AwsKmsKeyWrapperImpl(KmsAsyncClient client, String keyId, Map<String, String> encryptionContext, KeyFileTrust keyFileTrust) {
        this.client = Objects.requireNonNull(client, "client");
        Objects.requireNonNull(keyId, "keyId");
        if (keyId.isBlank())
            throw new IllegalArgumentException("keyId must not be empty or whitespace.");
        this.keyId = keyId;
        this.keyFileTrust = keyFileTrust != null ? keyFileTrust : KeyFileTrust.ADMINISTRATORS_ONLY;

        if (encryptionContext == null || encryptionContext.isEmpty()) {
            this.encryptionContext = null;
        } else {
            // Sorted by key (String order is ordinal), so every request serializes it the same way.
            var copy = new TreeMap<String, String>();
            for (var entry : encryptionContext.entrySet()) {
                var key = entry.getKey();
                if (key == null || key.isEmpty())
                    throw new IllegalArgumentException("Encryption context keys must not be empty.");
                copy.put(key, Objects.requireNonNull(entry.getValue(), "encryptionContext[\"" + key + "\"]"));
            }
            this.encryptionContext = Collections.unmodifiableMap(copy);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @return completes with the number of bytes written to result; fails with a
     *         {@link CryptographicException} when KMS refused the request or could not be reached
     *         (the AWS exception is the cause), or returned a wrapped DEK over
     *         {@link WrappedKeyLimits#MAX_BYTES}, or with an {@link IllegalArgumentException} when
     *         result is too small for the wrapped DEK
     * @throws NullPointerException     plaintext or result is null
     * @throws IllegalArgumentException plaintext is empty or over {@link #MAX_PLAINTEXT_LENGTH} bytes
     */
    @Override
    public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(result, "result");
        if (plaintext.length == 0 || plaintext.length > MAX_PLAINTEXT_LENGTH)
            throw new IllegalArgumentException("KMS wraps 1-" + MAX_PLAINTEXT_LENGTH + " bytes; got " + plaintext.length + ".");

        // The request wraps this array without copying it, and the SDK may serialize the request
        // after encrypt() returns, so it is zeroed only once the call has completed.
        var buffer = plaintext.clone();
        var request = EncryptRequest.builder()
                .keyId(keyId)
                .plaintext(SdkBytes.fromByteArrayUnsafe(buffer))
                .encryptionContext(encryptionContext)
                .encryptionAlgorithm(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT)
                .build();

        var call = send(() -> client.encrypt(request));
        var completed = call.whenComplete((response, error) -> ArrayUtility.zeroMemory(buffer));
        return cancellable(completed.handle((response, error) -> {
            if (error != null)
                throw translate(error, "wrap");
            return copyWrapped(response.ciphertextBlob(), result, "wrap");
        }), call);
    }

    /**
     * {@inheritDoc}
     *
     * @return completes with the number of bytes written to result; fails with a
     *         {@link CryptographicException} when wrapped is empty or over
     *         {@link WrappedKeyLimits#MAX_BYTES}, or KMS refused it - tampered with, wrapped under
     *         another key, or under a different encryption context - or could not be reached (the
     *         AWS exception is the cause), or with an {@link IllegalArgumentException} when result
     *         is too small for the revealed key. On any failure after KMS is called, result is zeroed.
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

        var request = DecryptRequest.builder()
                .keyId(keyId)
                .ciphertextBlob(SdkBytes.fromByteArray(wrapped))
                .encryptionContext(encryptionContext)
                .encryptionAlgorithm(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT)
                .build();

        var call = send(() -> client.decrypt(request));
        return cancellable(call.handle((response, error) -> {
            try {
                if (error != null)
                    throw translate(error, "unwrap");

                var revealed = response.plaintext();
                if (revealed == null)
                    throw new CryptographicException("AWS KMS unwrap for key '" + keyId + "' returned no plaintext.");
                return copyRevealed(revealed, result);
            } catch (RuntimeException | Error e) {
                ArrayUtility.zeroMemory(result);
                throw e;
            }
        }), call);
    }

    /**
     * Has KMS generate a fresh {@link #GENERATED_KEY_LENGTH}-byte DEK and return it wrapped only
     * (GenerateDataKeyWithoutPlaintext) - the plaintext DEK never leaves KMS on this call.
     *
     * @param result the wrapped key
     * @return completes with the number of bytes written to the result; fails with a
     *         {@link CryptographicException} when KMS refused the request or could not be reached
     *         (the AWS exception is the cause), or returned a wrapped DEK over
     *         {@link WrappedKeyLimits#MAX_BYTES}, or with an {@link IllegalArgumentException} when
     *         result is too small for the wrapped DEK
     * @throws NullPointerException result is null
     */
    @Override
    public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
        Objects.requireNonNull(result, "result");
        var request = GenerateDataKeyWithoutPlaintextRequest.builder()
                .keyId(keyId)
                .keySpec(DataKeySpec.AES_256)
                .encryptionContext(encryptionContext)
                .build();

        var call = send(() -> client.generateDataKeyWithoutPlaintext(request));
        return cancellable(call.handle((response, error) -> {
            if (error != null)
                throw translate(error, "generate-and-wrap");
            return copyWrapped(response.ciphertextBlob(), result, "generate-and-wrap");
        }), call);
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
     * like an unwrapped key. The file is read on the calling thread; no KMS call is made.
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

    // The SDK's future, or a failed one if the call threw instead of returning one.
    private static <T> CompletableFuture<T> send(Supplier<CompletableFuture<T>> call) {
        try {
            return Objects.requireNonNull(call.get(), "The KMS client returned no future.");
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    // Cancelling the future a caller holds cancels the KMS request it is waiting on.
    private static <T> CompletableFuture<T> cancellable(CompletableFuture<T> result, CompletableFuture<?> call) {
        result.whenComplete((value, error) -> {
            if (result.isCancelled())
                call.cancel(true);
        });
        return result;
    }

    // Turns AWS failures - service refusals (AwsServiceException) and client-side ones such as
    // unresolvable credentials (SdkClientException) - into the CryptographicException every
    // KeyWrapper fails with, naming KMS's error code. Cancellation - a CancellationException, or the
    // SDK's AbortedException for an interrupted or aborted call - is left as it is, as is anything
    // that isn't an AWS failure.
    private RuntimeException translate(Throwable error, String operation) {
        while ((error instanceof CompletionException || error instanceof ExecutionException) && error.getCause() != null)
            error = error.getCause();

        if (error instanceof AwsServiceException e) {
            var details = e.awsErrorDetails();
            var code = details != null && details.errorCode() != null ? details.errorCode() : e.getClass().getSimpleName();
            return new CryptographicException("AWS KMS " + operation + " failed for key '" + keyId + "': " + code + " (HTTP " + e.statusCode() + ").", e);
        }
        if (error instanceof AbortedException e)
            return e;
        if (error instanceof SdkClientException e)
            return new CryptographicException("AWS KMS " + operation + " failed for key '" + keyId + "': " + e.getMessage(), e);
        if (error instanceof CancellationException e)
            return e;
        if (error instanceof RuntimeException e)
            return e;
        if (error instanceof Error e)
            throw e;
        return new CompletionException(error);
    }

    private int copyWrapped(SdkBytes ciphertext, byte[] result, String operation) {
        var length = ciphertext == null ? 0 : ciphertext.asByteBuffer().remaining();
        if (length == 0)
            throw new CryptographicException("AWS KMS " + operation + " for key '" + keyId + "' returned no ciphertext.");

        // A key file over the limit would be refused when read back, so refuse to produce one.
        if (length > WrappedKeyLimits.MAX_BYTES)
            throw new CryptographicException("AWS KMS " + operation + " for key '" + keyId + "' returned " + length
                    + " bytes; a wrapped DEK is at most " + WrappedKeyLimits.MAX_BYTES + ".");

        if (length > result.length)
            throw new IllegalArgumentException("The wrapped DEK is " + length + " bytes; result holds " + result.length + ".");

        ciphertext.asByteBuffer().get(result, 0, length);
        return length;
    }

    private static int copyRevealed(SdkBytes revealed, byte[] result) {
        // The SdkBytes' own array: it is meant to be immutable, but asByteArrayUnsafe returns the
        // array itself rather than a copy whenever it wraps all of one, as the SDK's unmarshaller
        // builds it. If it ever can't, the copy it returns is zeroed instead and the original is
        // out of reach, like the SDK's other copies (see the class comment).
        var plaintext = revealed.asByteArrayUnsafe();
        try {
            if (plaintext.length > result.length)
                throw new IllegalArgumentException("The revealed key is " + plaintext.length + " bytes; result holds " + result.length + ".");

            System.arraycopy(plaintext, 0, result, 0, plaintext.length);
            return plaintext.length;
        } finally {
            ArrayUtility.zeroMemory(plaintext);
        }
    }
}
