package io.github.runsecure.hkdfguard.pipeline.awssecretsmanager;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.pipeline.SecretPipelineWriterBase;
import io.github.runsecure.hkdfguard.pipeline.SecretRequest;
import io.github.runsecure.hkdfguard.remote.JsonReader;
import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

/**
 * The end of a provisioning pipeline: pulls a fixed list of secrets from AWS Secrets Manager,
 * encrypts each with a {@link PipelineDataProtector} as soon as it is read, and writes them out as
 * one file per secret - the folder layout FilePerSecretCacheImpl reads at runtime. It is independent
 * of hkdfguard-cache-awssecretsmanager's runtime cache, and of any key ring. Naming, encrypting,
 * keeping and writing are {@link SecretPipelineWriterBase}'s.
 * <pre>{@code
 * try (var protector = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), 3);
 *         var client = SecretsManagerAsyncClient.create();
 *         var writer = new AwsSecretsManagerSecretPipelineWriterImpl(client, protector,
 *                 List.of("prod/app#username", "prod/app#password", "prod/api-key"))) {
 *     writer.pullSecretsAsync().join();
 *     writer.writeProtectedSecretFiles(Path.of("C:\\HkdfGuardSecrets\\myapp"));
 *     // Then hand protector.getKeyAsBase64() to the wrap tool, and register the key at version 3.
 * }
 * }</pre>
 * <p>
 * A secret name is a Secrets Manager secret name, optionally with a key after '#': "prod/api-key"
 * reads the secret's whole SecretString, and "prod/app#password" the password member of a key/value
 * secret - a SecretString holding a JSON object, as the console stores one (written as prod__api-key
 * and prod__app__password). A member's string is read as its text; a number, true or false as its
 * JSON text. Each secret's current version (AWSCURRENT) is read with GetSecretValue, so the principal
 * needs only {@code secretsmanager:GetSecretValue} on them (and {@code kms:Decrypt} on a customer
 * managed key that encrypts them). A name holding '+', '=' or '@', which no file name can, is refused.
 * A SecretBinary is refused with an {@link InvalidSecretDataException}: the protector encrypts text.
 * A secret that doesn't exist (ResourceNotFoundException) is missing; any other AWS failure fails the
 * pull as the SDK's exception.
 * <p>
 * The secret never becomes a String. Each GetSecretValue carries a plugin of its own, for that
 * request only, as hkdfguard-cache-awssecretsmanager's does, whose interceptor collects the
 * successful response's body into an array of the library's own, encrypts the secret in it, and
 * hands the SDK's unmarshaller an empty object in its place, so the value never becomes the
 * response's SecretString; every array that held it is zeroed. What can't be zeroed is below the
 * SDK: the HTTP client's own buffers.
 * <p>
 * The {@link SecretsManagerAsyncClient} is the application's: it builds the client (credentials -
 * IRSA or EKS Pod Identity on EKS - region, HTTP client, timeouts, retries), and closes it. The
 * writer never closes it, and changes nothing on it: the capture is attached to each request, not to
 * the client. Cancelling the pull cancels the GetSecretValue call in progress.
 */
public final class AwsSecretsManagerSecretPipelineWriterImpl extends SecretPipelineWriterBase {
    /** The longest name Secrets Manager accepts for a secret. */
    public static final int MAX_SECRET_NAME_LENGTH = 512;

    private final SecretsManagerAsyncClient client;

    /**
     * @param client      the Secrets Manager client every call is made through. Not closed by the
     *                    writer; its owner closes it.
     * @param protector   encrypts every value read. Owned by the caller: the writer never closes it.
     * @param secretNames the secrets to pull, each a secret name with the key to read after '#' if
     *                    any. Copied: a later change to the list isn't seen.
     * @throws NullPointerException     client, protector or secretNames is null
     * @throws IllegalArgumentException secretNames is empty, or holds a null, a name Secrets Manager
     *                                  can't hold (with a key), one whose file name isn't one
     *                                  FilePerSecretCacheImpl can read, or two with the same file
     *                                  name, in any case
     */
    public AwsSecretsManagerSecretPipelineWriterImpl(SecretsManagerAsyncClient client, PipelineDataProtector protector, List<String> secretNames) {
        super(protector, secretNames, AwsSecretsManagerSecretPipelineWriterImpl::isValidSecretName);
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

    /**
     * {@inheritDoc}
     *
     * @throws AwsServiceException        any AWS failure but ResourceNotFoundException (access
     *                                    denied, a secret scheduled for deletion)
     * @throws InvalidSecretDataException the secret is a SecretBinary, the response isn't Secrets
     *                                    Manager's JSON, or a key/value secret holds a key twice
     */
    @Override
    protected void readSecret(String name, List<SecretRequest> requests, Map<String, String> values) {
        try {
            readSecretAsync(name, requests, values).join();
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
    protected CompletableFuture<Void> readSecretAsync(String name, List<SecretRequest> requests, Map<String, String> values) {
        // Filled by the capture, from the body in an array of its own; the response the SDK
        // unmarshals holds nothing, so it isn't read here. Cleared for each attempt the SDK makes.
        var read = newValues();
        var capture = new PipelineSecretCapture((body, length) -> {
            read.clear();
            protectValues(body, length, requests, read);
        });
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
                values.putAll(read);
                return null;
            }

            // A body the capture refused fails the call with whatever the SDK made of it; report
            // the capture's own failure instead.
            var refused = capture.failure();
            if (refused != null)
                throw refused;

            var cause = KeyWrapperFutures.unwrap(error);
            if (cause instanceof ResourceNotFoundException)
                return null; // missing: nothing handed over
            if (cause instanceof RuntimeException runtime)
                throw runtime;
            if (cause instanceof Error e)
                throw e;
            throw new CompletionException(cause);
        }), call);
    }

    // Encrypts the top-level SecretString of a GetSecretValue body, and each requested key it holds.
    private void protectValues(byte[] body, int length, List<SecretRequest> requests, Map<String, String> values) {
        var reader = new JsonReader(body, length);
        try {
            if (!reader.read() || reader.token() != Token.START_OBJECT)
                throw new InvalidSecretDataException("The response body isn't a JSON object.");

            var found = false;
            while (nextProperty(reader)) {
                var isText = reader.valueTextEquals("SecretString");
                var isBinary = !isText && reader.valueTextEquals("SecretBinary");
                reader.read();
                if (reader.token() != Token.STRING || reader.valueLength() == 0 || !(isText || isBinary)) {
                    reader.skip();
                    continue;
                }

                if (isBinary)
                    throw new InvalidSecretDataException("A SecretBinary can't be protected: the pipeline protector encrypts text.");
                if (found)
                    throw new InvalidSecretDataException("The response body holds more than one secret value.");
                found = true;
                protectSecretString(reader, requests, values);
            }
        } catch (JsonReader.Malformed e) {
            // Not chained: what the reader rejected may be in the secret.
            throw new InvalidSecretDataException("The response body isn't valid JSON (at byte " + e.position + " of line " + e.line + ").");
        }
    }

    // Unescapes the SecretString the reader is at into an array of its own, and encrypts it whole and
    // each requested key it holds.
    private void protectSecretString(JsonReader reader, List<SecretRequest> requests, Map<String, String> values) {
        // Unescaped, a string is never longer than it is escaped.
        var text = new byte[reader.valueLength()];
        try {
            protectSecret(text, reader.copyString(text), requests, values);
        } finally {
            ArrayUtility.zeroMemory(text);
        }
    }

    private static boolean nextProperty(JsonReader reader) {
        reader.read();
        return reader.token() == Token.PROPERTY_NAME;
    }

    // A successful response whose body never passed through the capture would hold the secret, and
    // nothing would be kept; refuse it rather than report the secret missing.
    private static void ensureCaptured(PipelineSecretCapture capture, GetSecretValueResponse response) {
        if (capture.captured())
            return;

        if (response.secretBinary() != null)
            ArrayUtility.zeroMemory(response.secretBinary().asByteArrayUnsafe());
        throw new IllegalStateException("The GetSecretValue response wasn't captured: the client ran no per-request plugin.");
    }
}
