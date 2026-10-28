package io.github.runsecure.hkdfguard.cache.azurekeyvault;

import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.policy.HttpLogDetailLevel;
import com.azure.core.http.policy.HttpLogOptions;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheCollectionImpl;
import io.github.runsecure.hkdfguard.cache.RemoteSecretCache;
import io.github.runsecure.hkdfguard.cache.SecretNameMatching;
import io.github.runsecure.hkdfguard.cache.SecretValueSink;
import java.util.Objects;
import org.slf4j.Logger;

/**
 * A {@link io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache} over the secrets in one
 * Azure Key Vault. The first lookup of a name that isn't cached yet reads that one secret (its
 * current version) with Get Secret; fetching, encryption, caching and telemetry are
 * {@link RemoteSecretCache}'s. This class never lists the vault's secrets, so the principal needs
 * only {@code get} on secrets (the Key Vault Secrets User role), never {@code list}.
 * <p>
 * Key Vault secret names are 1-{@value #MAX_SECRET_NAME_LENGTH} ASCII letters, digits and hyphens,
 * compared ignoring case, so "Db-Password" and "DB-PASSWORD" are one entry and one secret. Any other
 * name (a configuration path such as "ConnectionStrings:Admin", say) is reported missing without a
 * call - and is never spliced into a request URL, so the cache can sit in a
 * {@link ProtectedCacheCollectionImpl} beside sources with other naming rules.
 * <p>
 * A secret whose value is a JSON object, such as {"username":"app","password":"..."}, is cached whole
 * under its name and each member under "name#key" - "Db-Login#password" - all from one call (see
 * {@link RemoteSecretCache}). Keys are matched exactly, though secret names aren't.
 * <p>
 * A secret that doesn't exist (404) or whose value is empty is reported missing. Any other failure
 * (access denied, a disabled secret, the vault unreachable, a credential that can't get a token)
 * propagates as the Azure SDK's exception.
 * <p>
 * The secret never becomes a String. The cache builds its own SecretClient with a pipeline policy
 * that reads the response body off the network into an array of the library's own, takes the value
 * out of it, and hands SecretClient the body with the value blanked; every array holding the value
 * that the library can reach is zeroed. What can't be zeroed is below the pipeline: the HTTP
 * client's own buffers (TLS decryption, socket reads). decryptAsync and findMaxDecryptedLengthAsync
 * fetch on a virtual thread (see {@link RemoteSecretCache#fetchAsync}), which cancelling the lookup
 * interrupts.
 */
public final class AzureKeyVaultSecretCacheImpl extends RemoteSecretCache {
    /** The longest name Key Vault accepts for a secret. */
    public static final int MAX_SECRET_NAME_LENGTH = 127;

    private final SecretClient client;

    /**
     * A cache without a logger; see {@link #AzureKeyVaultSecretCacheImpl(SecretClientBuilder, KeyRing, Logger)}.
     *
     * @throws NullPointerException  builder or keyRing is null
     * @throws IllegalStateException the builder has no vault URL or credential
     */
    public AzureKeyVaultSecretCacheImpl(SecretClientBuilder builder, KeyRing keyRing) {
        this(builder, keyRing, null);
    }

    /**
     * A cache over the vault {@code builder} is set up for. No call is made until a secret is
     * requested.
     * <p>
     * The application configures the builder: the vault URL, the credential, and as it needs the
     * HTTP client, retry options, client options and its own policies. The cache then changes the
     * caller's builder - the SDK has no way to copy one, nor to read one back - before building its
     * own SecretClient from it:
     * <ul>
     * <li>It adds its capture policy, after the retry policy, so it runs on every attempt. The policy
     * acts only on the cache's own fetches: another client built from the same builder reads secrets
     * as usual. Each cache built from the same builder adds the policy again; the extra copies find
     * the value already blanked and do nothing, so prefer a fresh builder per cache.</li>
     * <li>It replaces any log options the caller set with the environment's defaults
     * ({@code new HttpLogOptions()}, which reads {@code AZURE_HTTP_LOG_DETAIL_LEVEL}), never logging
     * bodies: BODY becomes NONE, and BODY_AND_HEADERS becomes HEADERS. The SDK's logging policy runs
     * closer to the network than the capture policy, so logging response bodies would log every
     * secret's value; replacing the options, rather than refusing them as the .NET cache does, is
     * the only way to be sure, as a builder's options can't be read back.</li>
     * <li>It clears any HttpPipeline the caller set, which would otherwise replace the builder's
     * whole pipeline - the capture policy and the log options with it.</li>
     * </ul>
     * Changes made to the builder after the constructor returns don't reach the cache's client.
     *
     * @param builder sets up the cache's Key Vault client; changed as described above
     * @param keyRing supplies the key every fetched secret is encrypted under. Owned by the caller:
     *                the cache never closes keys.
     * @param logger  optional; see {@link RemoteSecretCache}
     * @throws NullPointerException  builder or keyRing is null
     * @throws IllegalStateException the builder has no vault URL or credential
     */
    public AzureKeyVaultSecretCacheImpl(SecretClientBuilder builder, KeyRing keyRing, Logger logger) {
        super(keyRing, SecretNameMatching.IGNORE_ASCII_CASE, logger);
        Objects.requireNonNull(builder, "builder");

        client = builder.pipeline(null)
                .httpLogOptions(withoutBodies(new HttpLogOptions()))
                .addPolicy(SecretCapturePolicy.INSTANCE)
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

    @Override
    protected boolean isValidName(String name) {
        return isValidSecretName(name);
    }

    @Override
    protected void fetch(String name, SecretValueSink value) {
        // The value reaches the sink through the capture policy; what SecretClient returns holds it
        // blanked, so it isn't read here.
        var capture = new SecretCapturePolicy.Capture(value);
        try {
            client.getSecretWithResponse(name, "", SecretCapturePolicy.context(capture));
        } catch (HttpResponseException e) {
            if (e.getResponse() != null && e.getResponse().getStatusCode() == 404)
                return;
            throw e;
        }

        if (!capture.captured())
            throw new IllegalStateException("Key Vault's response didn't pass through the cache's capture policy.");
    }
}
