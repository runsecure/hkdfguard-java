package io.github.runsecure.hkdfguard.cache.awssecretsmanager;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.cache.RemoteSecretCache;
import io.github.runsecure.hkdfguard.cache.SecretNameMatching;
import io.github.runsecure.hkdfguard.cache.SecretValueSink;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import org.slf4j.Logger;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

/**
 * A {@link io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache} over the secrets in
 * AWS Secrets Manager. The first lookup of a name that isn't cached yet reads that one secret's
 * current version (AWSCURRENT) with GetSecretValue; fetching, encryption, caching and telemetry are
 * {@link RemoteSecretCache}'s. This class never lists secrets (ListSecrets, BatchGetSecretValue), so
 * the principal needs only {@code secretsmanager:GetSecretValue} on the secrets it reads (and
 * {@code kms:Decrypt} on a customer managed key that encrypts them).
 * <p>
 * Names are matched exactly, as Secrets Manager matches them: "prod/Db" and "prod/db" are two
 * secrets and two entries. A name Secrets Manager can't hold - anything but 1-512 ASCII letters,
 * digits and /_+=.@- , such as the configuration path "ConnectionStrings:Admin" - is reported
 * missing without a call. ARNs aren't accepted: look secrets up by name.
 * <p>
 * A secret that doesn't exist (ResourceNotFoundException) or whose value is empty is reported
 * missing. Any other failure (access denied, a secret scheduled for deletion, AWS unreachable, no
 * credentials) propagates as the AWS exception, and a response body that can't be trusted as
 * Secrets Manager's as an {@link io.github.runsecure.hkdfguard.cache.InvalidSecretDataException}. A
 * SecretString is cached as its UTF-8 bytes; a SecretBinary as its bytes.
 * <p>
 * A key/value secret - a SecretString holding a JSON object, as the console stores one - is cached
 * whole under its name and each member under "name#key" - "prod/app#password" - all from one
 * GetSecretValue (see {@link RemoteSecretCache}). A SecretBinary is never split.
 * <p>
 * The secret never becomes a String. Each GetSecretValue carries a plugin of its own, for that
 * request only, whose interceptor collects the successful response's body into an array of this
 * library's, takes SecretString or SecretBinary out of it (see
 * {@link io.github.runsecure.hkdfguard.cache.SecretJsonBody}), and hands the SDK's unmarshaller the
 * body with both replaced by "". Every array that held the value is zeroed, as are the HTTP
 * client's buffers where it hands over writable ones; what can't be zeroed is below the SDK: the
 * HTTP client's own buffers (TLS decryption, socket reads) and, on the JVM, any copy a compacting
 * collector left behind.
 * <p>
 * The {@link SecretsManagerAsyncClient} is the application's: it builds the client (credentials,
 * region, HTTP client, timeouts, retries), keeps it open for as long as anything uses this cache,
 * and closes it. This cache never closes it, and changes nothing on it: the capture is attached to
 * each request, not to the client. decryptAsync and findMaxDecryptedLengthAsync fetch without
 * blocking, and cancelling one that started a fetch cancels the GetSecretValue call; decrypt and
 * findMaxDecryptedLength block the calling thread until AWS answers.
 */
public final class AwsSecretsManagerSecretCacheImpl extends RemoteSecretCache {
    /** The longest name Secrets Manager accepts for a secret. */
    public static final int MAX_SECRET_NAME_LENGTH = 512;

    private final SecretsManagerAsyncClient client;

    /**
     * A cache reading secrets through {@code client}, encrypting each under {@code keyRing}'s
     * current key.
     *
     * @param client  the Secrets Manager client every call is made through. Not closed by this
     *                cache; its owner (typically the application, or its dependency injection
     *                container) closes it.
     * @param keyRing supplies the key every fetched secret is encrypted under. Owned by the caller:
     *                the cache never closes keys.
     * @param logger  optional; see {@link RemoteSecretCache}
     * @throws NullPointerException client or keyRing is null
     */
    public AwsSecretsManagerSecretCacheImpl(SecretsManagerAsyncClient client, KeyRing keyRing, Logger logger) {
        super(keyRing, SecretNameMatching.EXACT, logger);
        this.client = Objects.requireNonNull(client, "client");
    }

    /**
     * Whether Secrets Manager accepts name as a secret name: 1-512 ASCII letters, digits and /_+=.@-
     *
     * @param name the name; null is not one
     * @return true if Secrets Manager can hold a secret by that name
     */
    public static boolean isValidSecretName(String name) {
        if (name == null || name.isEmpty() || name.length() > MAX_SECRET_NAME_LENGTH)
            return false;

        for (var i = 0; i < name.length(); i++) {
            var c = name.charAt(i);
            var valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '/' || c == '_' || c == '+' || c == '=' || c == '.' || c == '@' || c == '-';
            if (!valid)
                return false;
        }
        return true;
    }

    @Override
    protected boolean isValidName(String name) {
        return isValidSecretName(name);
    }

    @Override
    protected void fetch(String name, SecretValueSink value) {
        try {
            fetchAsync(name, value).join();
        } catch (CompletionException | CancellationException e) {
            var cause = KeyWrapperFutures.unwrap(e);
            if (cause instanceof RuntimeException runtime)
                throw runtime;
            if (cause instanceof Error error)
                throw error;
            throw e;
        }
    }

    @Override
    protected CompletableFuture<Void> fetchAsync(String name, SecretValueSink value) {
        // The value reaches the sink through the capture; the response holds it as "", so it isn't
        // read here.
        var capture = new SecretCapture(value);
        var request = GetSecretValueRequest.builder()
                .secretId(name)
                .overrideConfiguration(o -> o.addPlugin(capture))
                .build();

        CompletableFuture<GetSecretValueResponse> call;
        try {
            call = Objects.requireNonNull(client.getSecretValue(request), "The Secrets Manager client returned no future.");
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }

        return KeyWrapperFutures.cancelling(call.handle((response, error) -> {
            if (error == null) {
                ensureCaptured(capture, response);
                return null;
            }

            // A body the capture refused fails the call with whatever the SDK made of it; report
            // the capture's own failure instead.
            var refused = capture.failure();
            if (refused != null)
                throw refused;

            var cause = KeyWrapperFutures.unwrap(error);
            if (cause instanceof ResourceNotFoundException)
                return null;
            if (cause instanceof RuntimeException runtime)
                throw runtime;
            if (cause instanceof Error e)
                throw e;
            throw new CompletionException(cause);
        }), call);
    }

    // A successful response whose body never passed through the capture would hold the secret, and
    // nothing would be cached; refuse it rather than report the secret missing.
    private static void ensureCaptured(SecretCapture capture, GetSecretValueResponse response) {
        if (capture.captured())
            return;

        if (response.secretBinary() != null)
            ArrayUtility.zeroMemory(response.secretBinary().asByteArrayUnsafe());
        throw new IllegalStateException("The GetSecretValue response wasn't captured: the client ran no per-request plugin.");
    }
}
