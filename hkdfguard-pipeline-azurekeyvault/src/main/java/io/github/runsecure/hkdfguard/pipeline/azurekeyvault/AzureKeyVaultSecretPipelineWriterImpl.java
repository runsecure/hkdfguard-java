package io.github.runsecure.hkdfguard.pipeline.azurekeyvault;

import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.policy.HttpLogDetailLevel;
import com.azure.core.http.policy.HttpLogOptions;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.pipeline.SecretPipelineWriterBase;
import io.github.runsecure.hkdfguard.pipeline.SecretRequest;
import io.github.runsecure.hkdfguard.remote.JsonReader;
import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The end of a provisioning pipeline: pulls a fixed list of secrets from one Azure Key Vault,
 * encrypts each with a {@link PipelineDataProtector} as soon as it is read, and writes them out as
 * one file per secret - the folder layout FilePerSecretCacheImpl reads at runtime. It is independent
 * of hkdfguard-cache-azurekeyvault's runtime cache, and of any key ring, with its own SecretClient.
 * Naming, encrypting, keeping and writing are {@link SecretPipelineWriterBase}'s.
 * <pre>{@code
 * var builder = new SecretClientBuilder()
 *         .vaultUrl("https://myvault.vault.azure.net/")
 *         .credential(new DefaultAzureCredentialBuilder().build());
 * try (var protector = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), 3);
 *         var writer = new AzureKeyVaultSecretPipelineWriterImpl(builder, protector,
 *                 List.of("Db-Login#username", "Db-Login#password", "Api-Key"))) {
 *     writer.pullSecretsAsync().join();
 *     writer.writeProtectedSecretFiles(Path.of("C:\\HkdfGuardSecrets\\myapp"));
 *     // Then hand protector.getKeyAsBase64() to the wrap tool, and register the key at version 3.
 * }
 * }</pre>
 * <p>
 * A secret name is a Key Vault secret name - 1-127 ASCII letters, digits and hyphens - optionally
 * with a key after '#': "Api-Key" reads the secret's whole value, and "Db-Login#password" the
 * password member of a secret whose value is a JSON object (written as Api-Key and
 * Db-Login__password). A member's string is read as its text; a number, true or false as its JSON
 * text. Each secret's current version is read with Get Secret, so the principal needs only
 * {@code get} on secrets (the Key Vault Secrets User role), never {@code list}. Key Vault compares
 * names ignoring case; so do file names, so two names differing only in case are refused. A secret
 * that doesn't exist (404) is missing; any other failure (access denied, a disabled secret, the vault
 * unreachable, a credential that can't get a token) fails the pull as the Azure SDK's exception.
 * <p>
 * The writer's SecretClient has a pipeline policy that reads the response body off the network into
 * an array of the library's own, encrypts the secret in it, and hands SecretClient an empty object in
 * its place, so the value never becomes a KeyVaultSecret's String; every array holding it is zeroed.
 * Retries and timeouts are the builder's. On AKS, Microsoft Entra Workload Identity supplies the
 * credential through DefaultAzureCredential or WorkloadIdentityCredential. Each read runs on a
 * virtual thread of its own, which cancelling the pull interrupts.
 */
public final class AzureKeyVaultSecretPipelineWriterImpl extends SecretPipelineWriterBase {
    /** The longest name Key Vault accepts for a secret. */
    public static final int MAX_SECRET_NAME_LENGTH = 127;

    private final SecretClient client;

    /**
     * A writer over the vault {@code builder} is set up for. No call is made until a pull.
     * <p>
     * The application configures the builder: the vault URL, the credential, and as it needs the
     * HTTP client, retry options, client options and its own policies. The writer then changes the
     * caller's builder - the SDK has no way to copy one, nor to read one back - before building its
     * own SecretClient from it, as hkdfguard-cache-azurekeyvault's cache does:
     * <ul>
     * <li>It adds its capture policy, after the retry policy, so it runs on every attempt. The policy
     * acts only on the writer's own reads: another client built from the same builder reads secrets
     * as usual. Prefer a fresh builder per writer.</li>
     * <li>It replaces any log options the caller set with the environment's defaults
     * ({@code new HttpLogOptions()}), never logging bodies: BODY becomes NONE, and BODY_AND_HEADERS
     * becomes HEADERS. The SDK's logging policy runs closer to the network than the capture policy,
     * so logging response bodies would log every secret's value; replacing the options, rather than
     * refusing them as the .NET writer does, is the only way to be sure, as a builder's options can't
     * be read back.</li>
     * <li>It clears any HttpPipeline the caller set, which would otherwise replace the builder's
     * whole pipeline - the capture policy and the log options with it.</li>
     * </ul>
     *
     * @param builder     sets up the writer's Key Vault client; changed as described above
     * @param protector   encrypts every value read. Owned by the caller: the writer never closes it.
     * @param secretNames the secrets to pull, each a secret name with the key to read after '#' if
     *                    any. Copied: a later change to the list isn't seen.
     * @throws NullPointerException     builder, protector or secretNames is null
     * @throws IllegalArgumentException secretNames is empty, or holds a null, a name Key Vault can't
     *                                  hold (with a key), one whose file name isn't one
     *                                  FilePerSecretCacheImpl can read, or two with the same file
     *                                  name, in any case
     * @throws IllegalStateException    the builder has no vault URL or credential
     */
    public AzureKeyVaultSecretPipelineWriterImpl(SecretClientBuilder builder, PipelineDataProtector protector, List<String> secretNames) {
        super(protector, secretNames, AzureKeyVaultSecretPipelineWriterImpl::isValidSecretName);
        Objects.requireNonNull(builder, "builder");

        client = builder.pipeline(null)
                .httpLogOptions(withoutBodies(new HttpLogOptions()))
                .addPolicy(PipelineSecretCapturePolicy.INSTANCE)
                .buildClient();
    }

    /** Whether Key Vault accepts name as a secret name: 1-127 ASCII letters, digits and hyphens. */
    public static boolean isValidSecretName(String name) {
        if (name == null || name.isEmpty() || name.length() > MAX_SECRET_NAME_LENGTH)
            return false;

        for (var i = 0; i < name.length(); i++) {
            var c = name.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'))
                return false;
        }
        return true;
    }

    /** options, logging no bodies: BODY becomes NONE, and BODY_AND_HEADERS becomes HEADERS. */
    static HttpLogOptions withoutBodies(HttpLogOptions options) {
        var level = options.getLogLevel();
        if (level == HttpLogDetailLevel.BODY)
            options.setLogLevel(HttpLogDetailLevel.NONE);
        else if (level == HttpLogDetailLevel.BODY_AND_HEADERS)
            options.setLogLevel(HttpLogDetailLevel.HEADERS);
        return options;
    }

    /**
     * {@inheritDoc}
     *
     * @throws HttpResponseException      any Key Vault failure but 404 (access denied, a disabled
     *                                    secret, the vault unreachable); a credential that can't get
     *                                    a token throws its own exception
     * @throws InvalidSecretDataException the response isn't Key Vault's JSON, or a JSON object value
     *                                    holds a key twice
     */
    @Override
    protected void readSecret(String name, List<SecretRequest> requests, Map<String, String> values) {
        // Filled by the client's capture policy, from the body in an array of its own, once per
        // attempt; what SecretClient returns holds nothing, so it isn't read here.
        var read = newValues();
        var capture = new PipelineSecretCapturePolicy.Capture((body, length) -> {
            read.clear();
            protectValues(body, length, requests, read);
        });
        try {
            client.getSecretWithResponse(name, "", PipelineSecretCapturePolicy.context(capture));
        } catch (HttpResponseException e) {
            if (e.getResponse() != null && e.getResponse().getStatusCode() == 404)
                return; // missing: nothing handed over
            throw e;
        }

        if (!capture.captured())
            throw new IllegalStateException("Key Vault's response didn't pass through the writer's capture policy.");
        values.putAll(read);
    }

    // Encrypts the top-level value of a Get Secret body, and each requested key it holds.
    private void protectValues(byte[] body, int length, List<SecretRequest> requests, Map<String, String> values) {
        var reader = new JsonReader(body, length);
        try {
            if (!reader.read() || reader.token() != Token.START_OBJECT)
                throw new InvalidSecretDataException("The response body isn't a JSON object.");

            var found = false;
            while (nextProperty(reader)) {
                var isValue = reader.valueTextEquals("value");
                reader.read();
                if (!isValue || reader.token() != Token.STRING) {
                    reader.skip();
                    continue;
                }
                if (found)
                    throw new InvalidSecretDataException("The response body holds more than one secret value.");
                found = true;

                // Unescaped, a string is never longer than it is escaped.
                var text = new byte[reader.valueLength()];
                try {
                    protectSecret(text, reader.copyString(text), requests, values);
                } finally {
                    ArrayUtility.zeroMemory(text);
                }
            }
        } catch (JsonReader.Malformed e) {
            // Not chained: what the reader rejected may be in the secret.
            throw new InvalidSecretDataException("The response body isn't valid JSON (at byte " + e.position + " of line " + e.line + ").");
        }
    }

    private static boolean nextProperty(JsonReader reader) {
        reader.read();
        return reader.token() == Token.PROPERTY_NAME;
    }
}
