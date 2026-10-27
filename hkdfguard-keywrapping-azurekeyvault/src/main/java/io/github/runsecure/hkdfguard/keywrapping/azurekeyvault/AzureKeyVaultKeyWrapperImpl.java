package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.HttpResponseException;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.UnwrapResult;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import io.github.runsecure.hkdfguard.securefile.TrustedKeyFile;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Protects (wraps) and reveals (unwraps) a DEK under an RSA key in Azure Key Vault, and signs every
 * wrapped DEK with a second, EC P-256 key in the vault. The private keys never enter this process;
 * unwrapping and signing are calls to Key Vault, authorized by the caller's Azure credential.
 * <p>
 * Why two keys: RSA-OAEP wrapping needs only the public key, which isn't secret, so without the
 * signature anyone could produce a wrapped DEK this wrapper would accept - holding a DEK they
 * chose, which the application would then encrypt new data under. Signing needs the signing key's
 * private half, held in Key Vault and usable only by principals granted {@code sign}. Unwrap checks
 * the signature before it unwraps anything, so a wrapped DEK proves it was made by a principal
 * allowed to sign: give that permission to the pipeline that creates key files, never to the
 * application. Each key does one job; the wrapper refuses the same key for both.
 * <p>
 * Both keys are pinned: a wrapped DEK records only the key versions it was made with, and the vault
 * and key names always come from the constructor. Rotating either key in Key Vault therefore needs
 * nothing here - existing key files keep naming the version that made them, which must stay enabled
 * while they're in use. Wrapped DEKs are byte for byte those of the .NET AzureKeyVaultKeyWrapper, so
 * a key file made by either is read by the other, given the same keys and context.
 * <p>
 * The optional context is bound into the signature, and must be given again, exactly, to reveal
 * the DEK: a key file made for one application can't be used by another that shares the keys.
 * Key Vault has no "generate data key", so {@link #generateAndWrapAsync} generates the DEK in this
 * process, wraps it, and zeroes it. Plaintext key bytes this class owns are zeroed once used: its
 * copy of the key sent to be wrapped, and its copy of the revealed key. The Azure SDK's own copies
 * - the request body, the response body, and the array inside the {@link UnwrapResult}, whose
 * getter returns a copy - aren't exposed, so they can't be zeroed and live until collected.
 * <p>
 * The wrapper builds one Key Vault client per key version it uses, and keeps it: each caches the
 * public key it verifies with, and a key ring's refresh unwraps under the same versions every
 * interval. Each method returns as soon as the first request is sent. Argument errors throw from
 * the call itself; everything else - a Key Vault refusal, an unreachable vault, a signature that
 * doesn't verify, a result too small - completes the future exceptionally. Cancelling a returned
 * future cancels the Key Vault request in flight.
 */
public final class AzureKeyVaultKeyWrapperImpl implements KeyWrapper {
    /** The length of the DEK {@link #generateAndWrapAsync} generates: 32 bytes (AES-256). */
    public static final int GENERATED_KEY_LENGTH = 32;

    /** The largest plaintext RSA-OAEP-256 wraps under a 2048-bit key, in bytes. */
    public static final int MAX_PLAINTEXT_LENGTH = 190;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeyVaultKeyId wrappingKey;
    private final KeyVaultKeyId signingKey;
    private final Function<String, KeyVaultKeyClient> clientFactory;
    private final Map<String, KeyVaultKeyClient> clients = new ConcurrentHashMap<>();
    private final byte[] context;
    private final KeyFileTrust keyFileTrust;

    /**
     * A wrapper binding no context, reading key files only administrators can have written
     * ({@link KeyFileTrust#ADMINISTRATORS_ONLY}), with default Key Vault clients.
     *
     * @param wrappingKeyId the RSA key that wraps every DEK; see {@link #AzureKeyVaultKeyWrapperImpl(String, String, TokenCredential, String, KeyFileTrust, Consumer)}
     * @param signingKeyId  the EC P-256 key that signs every wrapped DEK, in the same form
     * @param credential    authenticates every call to Key Vault, e.g. a managed identity
     * @throws NullPointerException     a key identifier or the credential is null
     * @throws IllegalArgumentException a key identifier isn't a Key Vault key's, or both name the same key
     */
    public AzureKeyVaultKeyWrapperImpl(String wrappingKeyId, String signingKeyId, TokenCredential credential) {
        this(wrappingKeyId, signingKeyId, credential, null, null, null);
    }

    /**
     * A wrapper reading key files only administrators can have written
     * ({@link KeyFileTrust#ADMINISTRATORS_ONLY}), with default Key Vault clients.
     *
     * @param wrappingKeyId the RSA key that wraps every DEK; see {@link #AzureKeyVaultKeyWrapperImpl(String, String, TokenCredential, String, KeyFileTrust, Consumer)}
     * @param signingKeyId  the EC P-256 key that signs every wrapped DEK, in the same form
     * @param credential    authenticates every call to Key Vault, e.g. a managed identity
     * @param context       bound into every wrapped DEK's signature and required again to reveal it;
     *                      null binds none. Not secret.
     * @throws NullPointerException     a key identifier or the credential is null
     * @throws IllegalArgumentException a key identifier isn't a Key Vault key's, both name the same
     *                                  key, or the context is too long or not well-formed text
     */
    public AzureKeyVaultKeyWrapperImpl(String wrappingKeyId, String signingKeyId, TokenCredential credential, String context) {
        this(wrappingKeyId, signingKeyId, credential, context, null, null);
    }

    /**
     * A wrapper with default Key Vault clients.
     *
     * @param wrappingKeyId the RSA key that wraps every DEK; see {@link #AzureKeyVaultKeyWrapperImpl(String, String, TokenCredential, String, KeyFileTrust, Consumer)}
     * @param signingKeyId  the EC P-256 key that signs every wrapped DEK, in the same form
     * @param credential    authenticates every call to Key Vault, e.g. a managed identity
     * @param context       bound into every wrapped DEK's signature and required again to reveal it;
     *                      null binds none. Not secret.
     * @param keyFileTrust  who besides the operating system's administrators may have written a key
     *                      file {@link #readKeyFileAsync} reads; null trusts administrators only
     * @throws NullPointerException     a key identifier or the credential is null
     * @throws IllegalArgumentException a key identifier isn't a Key Vault key's, both name the same
     *                                  key, or the context is too long or not well-formed text
     */
    public AzureKeyVaultKeyWrapperImpl(String wrappingKeyId, String signingKeyId, TokenCredential credential, String context,
            KeyFileTrust keyFileTrust) {
        this(wrappingKeyId, signingKeyId, credential, context, keyFileTrust, null);
    }

    /**
     * A wrapper over an RSA wrapping key and an EC P-256 signing key, binding {@code context} into
     * every wrapped DEK and trusting {@code keyFileTrust}, besides the administrators, to have
     * written its key files. No call is made until the wrapper is used.
     *
     * @param wrappingKeyId the RSA key that wraps every DEK (2048 or 3072 bits), as its key
     *                      identifier: {@code https://{vault}.vault.azure.net/keys/{name}},
     *                      optionally with {@code /{version}} to wrap under that version rather
     *                      than the current one
     * @param signingKeyId  the EC P-256 key that signs every wrapped DEK, in the same form
     * @param credential    authenticates every call to Key Vault, e.g. a managed identity
     * @param context       bound into every wrapped DEK's signature and required again to reveal it;
     *                      null binds none. Not secret.
     * @param keyFileTrust  who besides the operating system's administrators may have written a key
     *                      file {@link #readKeyFileAsync} reads; null trusts administrators only
     *                      ({@link KeyFileTrust#ADMINISTRATORS_ONLY})
     * @param clientOptions configures each Key Vault client's builder - its HTTP client, retry and
     *                      logging options, service version - before the wrapper sets the key and
     *                      the credential, which it always does itself; null for the defaults. The
     *                      HTTP client is otherwise the one azure-core finds on the class path.
     * @throws NullPointerException     a key identifier or the credential is null
     * @throws IllegalArgumentException a key identifier isn't a Key Vault key's, both name the same
     *                                  key, or the context is too long or not well-formed text
     */
    public AzureKeyVaultKeyWrapperImpl(String wrappingKeyId, String signingKeyId, TokenCredential credential, String context,
            KeyFileTrust keyFileTrust, Consumer<CryptographyClientBuilder> clientOptions) {
        this(wrappingKeyId, signingKeyId, clientFactory(credential, clientOptions), context, keyFileTrust);
    }

    AzureKeyVaultKeyWrapperImpl(String wrappingKeyId, String signingKeyId, Function<String, KeyVaultKeyClient> clientFactory,
            String context, KeyFileTrust keyFileTrust) {
        this.wrappingKey = KeyVaultKeyId.parse(Objects.requireNonNull(wrappingKeyId, "wrappingKeyId"));
        this.signingKey = KeyVaultKeyId.parse(Objects.requireNonNull(signingKeyId, "signingKeyId"));
        if (wrappingKey.sameKey(signingKey))
            throw new IllegalArgumentException("The wrapping and signing keys are both '" + wrappingKey.name()
                    + "'; use an RSA key to wrap and a separate EC P-256 key to sign.");

        this.clientFactory = Objects.requireNonNull(clientFactory, "clientFactory");
        this.context = WrappedDekEnvelope.encodeContext(context);
        this.keyFileTrust = keyFileTrust != null ? keyFileTrust : KeyFileTrust.ADMINISTRATORS_ONLY;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Wraps under the wrapping key (RSA-OAEP-256), then has the signing key sign the result (ES256).
     *
     * @return completes with the number of bytes written to result; fails with a
     *         {@link CryptographicException} when Key Vault refused a request or could not be
     *         reached (the Azure exception is the cause), answered for a key other than the one
     *         asked, or the wrapped DEK would be over {@link WrappedKeyLimits#MAX_BYTES} (an RSA key
     *         over 3072 bits) or its signature isn't ES256's, or with an
     *         {@link IllegalArgumentException} when result is too small for the wrapped DEK
     * @throws NullPointerException     plaintext or result is null
     * @throws IllegalArgumentException plaintext is empty or over {@link #MAX_PLAINTEXT_LENGTH} bytes
     */
    @Override
    public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(result, "result");
        if (plaintext.length == 0 || plaintext.length > MAX_PLAINTEXT_LENGTH)
            throw new IllegalArgumentException("Azure Key Vault wraps 1-" + MAX_PLAINTEXT_LENGTH + " bytes; got " + plaintext.length + ".");

        // The client may serialize the request after wrapKey() returns, so this copy is zeroed only
        // once the call has completed.
        var buffer = plaintext.clone();
        var calls = new Calls();
        var wrap = calls.send(() -> client(wrappingKey).wrapKey(KeyWrapAlgorithm.RSA_OAEP_256, buffer), "wrap", wrappingKey)
                .whenComplete((wrapped, error) -> ArrayUtility.zeroMemory(buffer));

        return calls.cancelling(wrap.thenCompose(wrapped -> {
            var unsigned = WrappedDekEnvelope.buildUnsigned(versionOf(wrapped.getKeyId(), wrappingKey, "wrap"), wrapped.getEncryptedKey());
            var length = unsigned.length + WrappedDekEnvelope.KEY_VERSION_LENGTH + WrappedDekEnvelope.SIGNATURE_LENGTH;
            if (length > WrappedKeyLimits.MAX_BYTES)
                throw new CryptographicException("The wrapped DEK would be " + length + " bytes; a wrapped DEK is at most "
                        + WrappedKeyLimits.MAX_BYTES + ". Use a 2048- or 3072-bit RSA key for '" + wrappingKey.name() + "'.");

            var signed = WrappedDekEnvelope.signedData(unsigned, unsigned.length, context);
            return calls.send(() -> client(signingKey).signData(SignatureAlgorithm.ES256, signed), "sign", signingKey)
                    .thenApply(signature -> WrappedDekEnvelope.write(unsigned, versionOf(signature.getKeyId(), signingKey, "sign"),
                            signature.getSignature(), result));
        }));
    }

    /**
     * {@inheritDoc}
     * <p>
     * Verifies the signature under the signing key version the wrapped DEK records first, and only
     * then unwraps under the recorded wrapping key version.
     *
     * @return completes with the number of bytes written to result; fails with a
     *         {@link CryptographicException} when wrapped isn't a wrapped DEK this wrapper wrote, its
     *         signature doesn't verify (forged, tampered with, or under a different context), Key
     *         Vault refused it, or Key Vault could not be reached (the Azure exception is the cause),
     *         or with an {@link IllegalArgumentException} when result is too small for the revealed
     *         key. On any failure, result is zeroed.
     * @throws NullPointerException wrapped or result is null
     */
    @Override
    public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
        Objects.requireNonNull(wrapped, "wrapped");
        Objects.requireNonNull(result, "result");

        WrappedDekEnvelope.Parts parts;
        try {
            parts = WrappedDekEnvelope.parse(wrapped);
        } catch (CryptographicException e) {
            ArrayUtility.zeroMemory(result);
            return CompletableFuture.failedFuture(e);
        }

        // The signature first: nothing reaches unwrapKey that a principal allowed to sign didn't make.
        var signed = WrappedDekEnvelope.signedData(wrapped, parts.unsignedLength(), context);
        var signedBy = signingKey.withVersion(parts.signingKeyVersion());
        var calls = new Calls();
        var failed = new AtomicBoolean();
        var unwrap = calls.send(() -> client(signedBy).verifyData(SignatureAlgorithm.ES256, signed, parts.signature()), "verify", signingKey)
                .thenCompose(verify -> {
                    if (!Boolean.TRUE.equals(verify.isValid()))
                        throw new CryptographicException("The wrapped DEK's signature doesn't verify under '" + signingKey.name() + "' version "
                                + parts.signingKeyVersion() + ": it was tampered with, wrapped under a different context, or not made by "
                                + "a principal allowed to sign.");

                    var wrappedBy = wrappingKey.withVersion(parts.wrappingKeyVersion());
                    return calls.send(() -> client(wrappedBy).unwrapKey(KeyWrapAlgorithm.RSA_OAEP_256, parts.wrappedDek()), "unwrap", wrappingKey);
                })
                .thenApply(revealed -> {
                    synchronized (failed) {
                        // Cancelled while the unwrap was answered: result is already zeroed, and stays so.
                        if (failed.get())
                            throw new CancellationException("The unwrap was cancelled.");
                        return copyRevealed(revealed, result);
                    }
                });

        // Registered on the future the caller gets, so a cancellation zeroes result too - after a copy
        // already under way, never before it.
        unwrap.whenComplete((length, error) -> {
            if (error != null) {
                synchronized (failed) {
                    failed.set(true);
                    ArrayUtility.zeroMemory(result);
                }
            }
        });
        return calls.cancelling(unwrap);
    }

    /**
     * Generates a fresh {@link #GENERATED_KEY_LENGTH}-byte DEK in this process, wraps and signs it,
     * and zeroes it - it is never returned.
     *
     * @param result the wrapped key
     * @return completes with the number of bytes written to the result; fails as
     *         {@link #wrapAsync} does
     * @throws NullPointerException result is null
     */
    @Override
    public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
        Objects.requireNonNull(result, "result");
        var dek = new byte[GENERATED_KEY_LENGTH];
        try {
            RANDOM.nextBytes(dek);
            // wrapAsync works on its own copy, taken before it returns.
            return wrapAsync(dek, result);
        } finally {
            ArrayUtility.zeroMemory(dek);
        }
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
     * like an unwrapped key. The file is read on the calling thread; no Key Vault call is made.
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

    static Function<String, KeyVaultKeyClient> clientFactory(TokenCredential credential, Consumer<CryptographyClientBuilder> clientOptions) {
        Objects.requireNonNull(credential, "credential");
        return keyId -> {
            var builder = new CryptographyClientBuilder();
            if (clientOptions != null)
                clientOptions.accept(builder);
            return KeyVaultKeyClient.over(builder.keyIdentifier(keyId).credential(credential).buildAsyncClient());
        };
    }

    private KeyVaultKeyClient client(KeyVaultKeyId key) {
        return clients.computeIfAbsent(key.toString(), clientFactory);
    }

    // The version of the key Key Vault reports having used, refusing an answer from any other key.
    private static String versionOf(String keyId, KeyVaultKeyId expected, String operation) {
        KeyVaultKeyId used;
        try {
            used = KeyVaultKeyId.parse(Objects.requireNonNull(keyId, "no key identifier"));
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new CryptographicException("Azure Key Vault " + operation + " for key '" + expected.name() + "' reported key '" + keyId
                    + "', which isn't a key identifier.", e);
        }

        if (!used.sameKey(expected) || used.version() == null)
            throw new CryptographicException("Azure Key Vault " + operation + " for key '" + expected.name() + "' reported key '" + keyId
                    + "' instead.");
        return used.version();
    }

    // Turns Azure failures - service refusals (HttpResponseException with a response) and
    // client-side ones such as a credential that can't get a token - into the CryptographicException
    // every KeyWrapper fails with. Cancellation is left as it is.
    private static RuntimeException translate(Throwable error, String operation, KeyVaultKeyId key) {
        while ((error instanceof CompletionException || error instanceof ExecutionException) && error.getCause() != null)
            error = error.getCause();

        if (error instanceof CancellationException e)
            return e;
        if (error instanceof CryptographicException e)
            return e;
        if (error instanceof Error e)
            throw e;
        if (error instanceof HttpResponseException e && e.getResponse() != null)
            return new CryptographicException("Azure Key Vault " + operation + " failed for key '" + key.name() + "': "
                    + KeyVaultErrors.code(e) + " (HTTP " + e.getResponse().getStatusCode() + ").", e);
        return new CryptographicException("Azure Key Vault " + operation + " failed for key '" + key.name() + "': " + error.getMessage(), error);
    }

    private static int copyRevealed(UnwrapResult unwrap, byte[] result) {
        // A copy of the SDK's array: UnwrapResult's getter never hands over its own.
        var revealed = unwrap.getKey();
        if (revealed == null)
            throw new CryptographicException("Azure Key Vault unwrap returned no key.");
        try {
            if (revealed.length > result.length)
                throw new IllegalArgumentException("The revealed key is " + revealed.length + " bytes; result holds " + result.length + ".");

            System.arraycopy(revealed, 0, result, 0, revealed.length);
            return revealed.length;
        } finally {
            ArrayUtility.zeroMemory(revealed);
        }
    }

    /**
     * The Key Vault calls one operation makes, one after another. Cancelling the operation's future
     * cancels whichever call is in flight, and any call sent after it.
     */
    private static final class Calls {
        private final AtomicReference<CompletableFuture<?>> current = new AtomicReference<>();
        private volatile boolean cancelled;

        /** The call's future, failing with {@link #translate}'s exception; one that throws instead of returning a future fails it too. */
        <T> CompletableFuture<T> send(Supplier<CompletableFuture<T>> call, String operation, KeyVaultKeyId key) {
            CompletableFuture<T> sent;
            if (cancelled) {
                // Not sent at all: the request would go out before it could be cancelled.
                sent = CompletableFuture.failedFuture(new CancellationException("The operation was cancelled."));
            } else {
                try {
                    sent = Objects.requireNonNull(call.get(), "The Key Vault client returned no future.");
                } catch (RuntimeException e) {
                    sent = CompletableFuture.failedFuture(e);
                }
                current.set(sent);
                // Cancelled while this call was being made.
                if (cancelled)
                    sent.cancel(true);
            }

            return sent.handle((value, error) -> {
                if (error != null)
                    throw translate(error, operation, key);
                return value;
            });
        }

        <T> CompletableFuture<T> cancelling(CompletableFuture<T> result) {
            result.whenComplete((value, error) -> {
                if (result.isCancelled()) {
                    cancelled = true;
                    var call = current.get();
                    if (call != null)
                        call.cancel(true);
                }
            });
            return result;
        }
    }
}
