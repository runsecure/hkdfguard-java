package io.github.runsecure.hkdfguard.pipeline.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultHttp;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultRequestException;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultTokenSource;
import io.github.runsecure.hkdfguard.pipeline.ResponseBody;
import io.github.runsecure.hkdfguard.pipeline.SecretPipelineWriterBase;
import io.github.runsecure.hkdfguard.pipeline.SecretRequest;
import io.github.runsecure.hkdfguard.remote.JsonReader;
import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.CharBuffer;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeoutException;

/**
 * The end of a provisioning pipeline: pulls a fixed list of secrets from one HashiCorp Vault KV
 * secrets engine, encrypts each with a {@link PipelineDataProtector} as soon as it is read, and
 * writes them out as one file per secret - the folder layout FilePerSecretCacheImpl reads at
 * runtime. It is independent of hkdfguard-cache-hashicorpvault's runtime cache, and of any key ring.
 * Naming, encrypting, keeping and writing are {@link SecretPipelineWriterBase}'s.
 * <pre>{@code
 * try (var protector = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), 3);
 *         var token = new StaticVaultTokenSource(vaultToken);
 *         var writer = new HashiCorpVaultSecretPipelineWriterImpl(address, token, protector,
 *                 List.of("myapp/db#username", "myapp/db#password", "myapp/api"), null)) {
 *     writer.pullSecretsAsync().join();
 *     writer.writeProtectedSecretFiles(Path.of("C:\\HkdfGuardSecrets\\myapp"));
 *     // Then hand protector.getKeyAsBase64() to the wrap tool, and register the key at version 3.
 * }
 * }</pre>
 * <p>
 * A secret name is a path within the engine, with the key to read after '#': "myapp/db#password"
 * reads the password key of the secret at myapp/db, and "myapp/db" reads its
 * {@link HashiCorpVaultPipelineOptions#defaultKey() default key} (written as myapp__db__password and
 * myapp__db). A string is read as its text; a number, true or false as its JSON text. A path that
 * isn't one - segments of ASCII letters, digits, '-', '_' and '.', no segment "." or "..", at most
 * {@link #MAX_SECRET_NAME_LENGTH} characters - is refused. Each secret is read once (GET on its path;
 * for KV version 2, its latest version), so the token's policy needs only {@code read}, never
 * {@code list}.
 * <p>
 * A secret that doesn't exist (404 with no errors, as Vault answers), whose latest version is
 * deleted or destroyed, or that has no such key, is missing. Any other answer (403, a 404 naming an
 * error such as a mount that doesn't exist, Vault sealed) fails the pull with a
 * {@link VaultRequestException} carrying Vault's status and errors. A request that fails
 * transiently is retried as {@link HashiCorpVaultPipelineOptions} says; once the retries are spent,
 * a failure without an answer fails the pull with an {@link UncheckedIOException} whose cause is the
 * {@link IOException}.
 * <p>
 * Vault's response is read into an array of the library's own, and every array holding a value is
 * zeroed. The Vault token comes from a {@link VaultTokenSource}, in plaintext - there is no key ring
 * yet to protect it with - copied into a char array for each secret and zeroed once its read is
 * done. java.net.http takes a header's value only as a String, though, and a Java String can't be
 * zeroed: each request's token becomes one String, referenced only by that request, which stays in
 * memory until the garbage collector reuses it, as with the transit key wrapper. Requests go to /v1/
 * under Vault's address, which must be https except on loopback, and the writer's own HttpClient
 * follows no redirects. Each read runs on a virtual thread of its own, which cancelling the pull
 * interrupts. Close the writer to release its connections.
 */
public final class HashiCorpVaultSecretPipelineWriterImpl extends SecretPipelineWriterBase {
    /** The longest secret path read. */
    public static final int MAX_SECRET_NAME_LENGTH = 512;

    private final HttpClient http;
    private final boolean ownsHttp;
    private final VaultTokenSource tokenSource;
    private final Duration timeout;
    private final long timeoutNanos;
    private final int retryCount;
    private final Duration retryDelay;
    private final String namespace;
    private final String readBase;
    private final List<String> dataPath;
    private volatile boolean closed;

    /**
     * @param address     Vault's address, e.g. https://vault.example.com:8200 - the same value as
     *                    VAULT_ADDR. Must be https, except on a loopback address. A path, if any, is
     *                    kept as a prefix (Vault behind a reverse proxy).
     * @param tokenSource supplies the token every read is made with. Owned by the caller: the writer
     *                    never closes it.
     * @param protector   encrypts every value read. Owned by the caller: the writer never closes it.
     * @param secretNames the secrets to pull, each a path with the key to read after '#' if any.
     *                    Copied: a later change to the list isn't seen.
     * @param options     the KV engine read and how to reach it; null for KV version 2 at "secret",
     *                    reading the key "value"
     * @throws NullPointerException     address, tokenSource, protector or secretNames is null
     * @throws IllegalArgumentException secretNames is empty, or holds a null, a name that isn't a
     *                                  path (with a key), one whose file name isn't one
     *                                  FilePerSecretCacheImpl can read, or two with the same file
     *                                  name, in any case; or the options are invalid: a mount path,
     *                                  default key or namespace that isn't one, a timeout that isn't
     *                                  positive, a retry count or delay out of range, an HttpClient
     *                                  that follows redirects without allowRedirects, or TLS options
     *                                  given with an HttpClient or that can't be read; or address
     *                                  isn't https (or http on loopback), or holds credentials, a
     *                                  query or a fragment
     */
    public HashiCorpVaultSecretPipelineWriterImpl(URI address, VaultTokenSource tokenSource, PipelineDataProtector protector,
            List<String> secretNames, HashiCorpVaultPipelineOptions options) {
        super(protector, secretNames, HashiCorpVaultSecretPipelineWriterImpl::isValidSecretName, orDefaults(options).defaultKey());
        this.tokenSource = Objects.requireNonNull(tokenSource, "tokenSource");
        options = orDefaults(options);
        var apiBase = VaultHttp.apiBase(address, "a token");

        VaultHttp.checkSettings(options.mountPath(), options.namespace(), options.timeout(), options.retryCount(), options.retryDelay());
        var supplied = options.httpClient();
        VaultHttp.checkRedirects(supplied, options.allowRedirects());

        this.timeout = options.timeout();
        this.timeoutNanos = VaultHttp.saturatedNanos(timeout);
        this.retryCount = options.retryCount();
        this.retryDelay = options.retryDelay();
        this.namespace = options.namespace();
        if (options.kvVersion() == VaultKvVersion.V2) {
            this.readBase = apiBase + options.mountPath() + "/data/";
            this.dataPath = List.of("data", "data");
        } else {
            this.readBase = apiBase + options.mountPath() + "/";
            this.dataPath = List.of("data");
        }

        // Follows no redirects: one would carry X-Vault-Token wherever it points.
        this.ownsHttp = supplied == null;
        this.http = VaultHttp.httpClient(supplied, options.tls());
    }

    /**
     * Whether path is a secret's path: '/'-separated segments of ASCII letters, digits, '-', '_' and
     * '.', no segment "." or "..", at most {@link #MAX_SECRET_NAME_LENGTH} characters, as Vault takes
     * it.
     */
    public static boolean isValidSecretName(String path) {
        return path != null && !path.isEmpty() && path.length() <= MAX_SECRET_NAME_LENGTH && VaultHttp.isValidPath(path);
    }

    /**
     * Releases the writer's connections by closing its own HttpClient, which waits for requests in
     * flight (each bounded by the timeout); a supplied HttpClient is left open. A pull afterwards
     * fails with IllegalStateException.
     */
    @Override
    public void close() {
        closed = true;
        if (ownsHttp)
            http.close();
    }

    /**
     * {@inheritDoc}
     *
     * @throws VaultRequestException      Vault refused the read
     * @throws UncheckedIOException       Vault couldn't be reached, once the retries were spent
     * @throws InvalidSecretDataException the response isn't Vault's JSON, or holds a key twice
     * @throws IllegalStateException      the token source supplied no token, or the writer is closed
     * @throws CancellationException      the thread reading was interrupted
     */
    @Override
    protected void readSecret(String name, List<SecretRequest> requests, Map<String, String> values) {
        if (closed)
            throw new IllegalStateException("This HashiCorp Vault secret pipeline writer has been closed.");

        // Zeroed once the read is done. Asked for once per secret; a source's failure is its own to
        // retry, so isn't retried here.
        var token = new char[VaultHttp.MAX_TOKEN_LENGTH];
        try {
            var tokenLength = copyToken(token);

            // An attempt encrypts nothing until it has read the whole body, so a failed one hands
            // nothing over.
            var read = VaultHttp.withRetries(retryCount, retryDelay, () -> closed, () -> read(name, token, tokenLength, requests),
                    HashiCorpVaultSecretPipelineWriterImpl::cancelled);
            values.putAll(read);
        } finally {
            ArrayUtility.zeroMemory(token);
        }
    }

    private static HashiCorpVaultPipelineOptions orDefaults(HashiCorpVaultPipelineOptions options) {
        return options != null ? options : HashiCorpVaultPipelineOptions.builder().build();
    }

    // Has the token source copy the token into token, waited for within the timeout; returns its
    // length. Refused unless it is a token that fits.
    private int copyToken(char[] token) {
        var future = tokenSource.copyTokenAsync(token);
        if (future == null)
            throw new IllegalStateException("The Vault token source returned no future.");

        // A failure, never a cancellation: nobody cancelled this pull.
        Integer length = VaultHttp.await(future, timeoutNanos,
                () -> new CompletionException(new TimeoutException("The Vault token source supplied no token within " + timeout + ".")),
                HashiCorpVaultSecretPipelineWriterImpl::cancelled);

        if (length == null || length <= 0 || length > token.length || !VaultHttp.isValidToken(CharBuffer.wrap(token, 0, length)))
            throw new IllegalStateException("The Vault token source supplied no token, or one that isn't a token: printable ASCII, with no spaces.");
        return length;
    }

    // One attempt: one request, and Vault's whole response, within the attempt's timeout.
    private Map<String, String> read(String path, char[] token, int tokenLength, List<SecretRequest> requests)
            throws IOException, InterruptedException {
        var deadline = System.nanoTime() + timeoutNanos;

        // The one String the token becomes: java.net.http takes a header's value only as one. It is
        // referenced only by this request, so lives no longer than it, until collected.
        var request = VaultHttp.newRequest(URI.create(readBase + path), timeout, namespace).GET()
                .header(VaultHttp.TOKEN_HEADER, new String(token, 0, tokenLength))
                .build();
        return VaultHttp.send(http, request, deadline, response -> readResponse(path, response.statusCode(), response.body(), requests),
                () -> "Vault's response to the read of '" + path + "' took longer than " + timeout + ".");
    }

    private Map<String, String> readResponse(String path, int status, InputStream stream, List<SecretRequest> requests) throws IOException {
        try (var body = ResponseBody.read(stream)) {
            if (status >= 200 && status < 300)
                return protectValues(body.buffer(), body.length(), requests);

            // An error response holds no secret: read whole, as Vault's error list.
            var errors = VaultHttp.readErrors(body.buffer(), body.length());

            // Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version
            // 2 secret whose latest version is deleted, with its metadata and none. A 404 naming an
            // error (no such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
            if (status == 404 && errors != null && errors.isEmpty())
                return Map.of();

            var detail = errors != null && !errors.isEmpty() ? ": " + String.join("; ", errors) : "";
            throw new VaultRequestException("Vault refused to read '" + path + "': " + status + VaultHttp.reasonPhrase(status) + detail, status);
        }
    }

    // Encrypts the value of each requested key in the secret's data object, by file name.
    private Map<String, String> protectValues(byte[] json, int length, List<SecretRequest> requests) {
        var values = newValues();
        var reader = new JsonReader(json, length);
        try {
            if (!reader.read() || reader.token() != Token.START_OBJECT)
                throw new InvalidSecretDataException("Vault's response isn't a JSON object.");
            if (!moveToObject(reader, dataPath))
                return values;

            // The data object, copied whole for protectKeys to read; zeroed once it has.
            var start = reader.tokenStart();
            reader.skip();
            var data = Arrays.copyOfRange(json, start, reader.bytesConsumed());
            try {
                protectKeys(data, data.length, requests, values);
            } finally {
                ArrayUtility.zeroMemory(data);
            }
            return values;
        } catch (JsonReader.Malformed e) {
            // Not chained: what the reader rejected may be in the secret.
            throw new InvalidSecretDataException("Vault's response isn't valid JSON (at byte " + e.position + " of line " + e.line + ").");
        }
    }

    // Leaves the reader at the start of the object path leads to; false if it leads to none.
    private static boolean moveToObject(JsonReader reader, List<String> path) {
        for (var name : path) {
            var found = false;
            while (!found && nextProperty(reader)) {
                var isNext = reader.valueTextEquals(name);
                reader.read();
                if (isNext && reader.token() == Token.START_OBJECT)
                    found = true;
                else
                    reader.skip();
            }

            if (!found)
                return false;
        }
        return true;
    }

    private static boolean nextProperty(JsonReader reader) {
        reader.read();
        return reader.token() == Token.PROPERTY_NAME;
    }

    private static CancellationException cancelled() {
        return new CancellationException("The read from Vault was abandoned: the thread reading it was interrupted.");
    }
}
