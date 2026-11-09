package io.github.runsecure.hkdfguard.cache.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.cache.ErrorResponseBody;
import io.github.runsecure.hkdfguard.cache.RemoteSecretCache;
import io.github.runsecure.hkdfguard.cache.SecretJsonBody;
import io.github.runsecure.hkdfguard.cache.SecretNameMatching;
import io.github.runsecure.hkdfguard.cache.SecretValueSink;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultHttp;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultRequestException;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultTokenProvider;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;

/**
 * A protected read-only cache over the secrets in one HashiCorp Vault KV secrets engine. The first
 * lookup of a name that isn't cached yet reads that one secret (GET on its path; for KV version 2,
 * its latest version); fetching, encryption, caching and telemetry are {@link RemoteSecretCache}'s.
 * This class never lists secrets, so the token's policy needs only {@code read} on the paths it
 * reads, never {@code list}.
 * <p>
 * A name is a secret's path within the engine, with the key to read after '#': "myapp/db#password"
 * reads the password key of the secret at myapp/db, and "myapp/db" reads its
 * {@link HashiCorpVaultSecretCacheOptions#defaultKey() default key}. One read caches every key the
 * secret holds, so the first lookup of any of them reads the secret once and the rest are already
 * cached. A string is cached as its UTF-8 bytes; a number, true or false as its JSON text; a null,
 * object or array value isn't cached. Paths are matched exactly, as Vault matches them, and so are
 * keys. A path that isn't one - segments of ASCII letters, digits, '-', '_' and '.', no segment "."
 * or "..", at most {@link #MAX_SECRET_NAME_LENGTH} characters, such as the configuration path
 * "ConnectionStrings:Admin" - is reported missing without a call.
 * <p>
 * A secret that doesn't exist (404 with no errors, as Vault answers), whose latest version is
 * deleted or destroyed, or that has no such key, or whose value there is empty or isn't cached, is
 * reported missing. A KV version 2 engine read as version 1 is not: Vault's 404 then warns that the
 * path is invalid for a versioned engine, and the read fails with a {@link VaultRequestException}
 * saying so. The other mismatch can't be told apart - a version 1 engine read as version 2 holds
 * nothing at {mount}/data/{path} - so every secret reads as missing. Any other answer (403 for a token that is invalid or not allowed to read the
 * path, a 404 naming an error such as a mount that doesn't exist, a redirect, Vault sealed)
 * propagates as a {@link VaultRequestException} carrying Vault's status and errors. A request that
 * fails transiently - no answer, a connection lost mid-response, a timed-out attempt, 429 or a 5xx
 * other than 501 - is first retried {@link HashiCorpVaultSecretCacheOptions#retryCount()} times
 * (3-10), waiting {@link HashiCorpVaultSecretCacheOptions#retryDelay()} and doubling, up to 10
 * seconds, plus a random 0-100 ms each time so clients reconnecting together spread out. Once the
 * retries are spent, a failure without an answer propagates as an {@link UncheckedIOException}
 * whose cause is the {@link IOException} (an {@link HttpTimeoutException} for a timed-out attempt).
 * <p>
 * Authentication isn't the cache's: every fetch asks its {@link VaultTokenProvider} for a token,
 * once, so a provider can log in, renew and replace tokens however it likes. A provider's failure
 * propagates as it is (a checked one wrapped: an IOException in an UncheckedIOException, anything
 * else in a CompletionException), and isn't retried; a provider that hasn't answered within the
 * timeout fails the fetch with a {@link CompletionException} whose cause is a
 * {@link TimeoutException} - a failure, not a cancellation, since nobody cancelled the fetch. The
 * token is handed over protected
 * - encrypted by the cache's token protector, a protector on the key ring
 * ({@code keyRing.createProtector(TOKEN_PURPOSE)}) - and a fetch given one that isn't fails with
 * IllegalStateException. It is decrypted only as each request is built, into a char array that is
 * zeroed at once. java.net.http takes a header's value only as a String, though, and a Java String
 * can't be zeroed: each request's token becomes one String, made for that request alone and
 * referenced by nothing once it has been sent, which stays in memory until the garbage collector
 * reuses it. So do the request's header buffers inside java.net.http (and, over TLS, its
 * encryption buffers), which this class can't reach.
 * <p>
 * Requests go to /v1/ under Vault's address, which must be https except on loopback. The cache's
 * own HttpClient follows no redirects, which would carry the token elsewhere. A fetch through
 * decrypt or findMaxDecryptedLength runs on the calling thread, blocking it until Vault answers or
 * {@link HashiCorpVaultSecretCacheOptions#timeout()} passes (per attempt, covering the response's
 * headers and its whole body); through decryptAsync or findMaxDecryptedLengthAsync it runs on a
 * virtual thread of its own. Interrupting the thread a fetch runs on - which cancelling an
 * asynchronous lookup that started the fetch does - abandons the request or the wait between
 * retries: the fetch fails with a {@link CancellationException}, the thread's interrupt status set
 * again.
 * <p>
 * The secret never becomes a String. The response body is read straight off java.net.http's stream
 * into an array of the library's own, and the value is unescaped into another and encrypted from
 * there ({@link SecretJsonBody}); every array holding it is zeroed. What can't be zeroed is below
 * that stream: java.net.http's own buffers (TLS decryption, socket reads). Close the cache to
 * release its connections.
 */
public final class HashiCorpVaultSecretCacheImpl extends RemoteSecretCache implements AutoCloseable {
    /** The longest secret path looked up. */
    public static final int MAX_SECRET_NAME_LENGTH = 512;

    /**
     * The purpose to create the token protector with - {@code keyRing.createProtector(TOKEN_PURPOSE)}
     * - so a token protected for the cache can't be decrypted as anything else, nor anything else as
     * it.
     */
    public static final String TOKEN_PURPOSE = "HkdfGuard.Cache.HashiCorpVault.Token";

    // How a KV version 2 engine's 404 warns of a path a version 1 read made.
    private static final String VERSIONED_ENGINE_WARNING = "Invalid path for a versioned K/V secrets engine";

    private final HttpClient http;
    private final boolean ownsHttp;
    private final VaultTokenProvider tokenProvider;
    private final DataProtector tokenProtector;
    private final Duration timeout;
    private final long timeoutNanos;
    private final int retryCount;
    private final Duration retryDelay;
    private final String namespace;
    private final String readBase;
    private final List<String> dataPath;
    private final String defaultKey;
    private volatile boolean closed;

    /**
     * @param address        Vault's address, e.g. https://vault.example.com:8200 - the same value
     *                       as VAULT_ADDR. Must be https, except on a loopback address (a local
     *                       Vault Agent or dev server). A path, if any, is kept as a prefix (Vault
     *                       behind a reverse proxy).
     * @param tokenProvider  supplies the token every read is made with, protected by tokenProtector
     * @param tokenProtector decrypts the token tokenProvider supplies: a protector on the key ring,
     *                       {@code keyRing.createProtector(TOKEN_PURPOSE)}
     * @param keyRing        supplies the key every fetched secret is encrypted under. Owned by the
     *                       caller: the cache never closes keys.
     * @param options        the KV engine read and how to reach it; null for KV version 2 at
     *                       "secret", reading the key "value"
     * @param logger         optional; see {@link RemoteSecretCache}
     * @throws NullPointerException     address, tokenProvider, tokenProtector or keyRing is null
     * @throws IllegalArgumentException address isn't https (or http on loopback), or holds
     *                                  credentials, a query or a fragment; or the mount path,
     *                                  default key or namespace isn't one; or the timeout isn't
     *                                  positive, the retry count isn't 3-10 or the retry delay
     *                                  isn't zero to 10 seconds; the HttpClient follows
     *                                  redirects without allowRedirects; or TLS options are given
     *                                  with an HttpClient, or can't be read
     */
    public HashiCorpVaultSecretCacheImpl(URI address, VaultTokenProvider tokenProvider, DataProtector tokenProtector, KeyRing keyRing,
            HashiCorpVaultSecretCacheOptions options, Logger logger) {
        super(keyRing, SecretNameMatching.EXACT, logger);
        this.tokenProvider = Objects.requireNonNull(tokenProvider, "tokenProvider");
        this.tokenProtector = Objects.requireNonNull(tokenProtector, "tokenProtector");
        if (options == null)
            options = HashiCorpVaultSecretCacheOptions.builder().build();
        var apiBase = VaultHttp.apiBase(address, "a token");

        VaultHttp.checkSettings(options.mountPath(), options.namespace(), options.timeout(), options.retryCount(), options.retryDelay());
        if (!isValidKey(options.defaultKey()))
            throw new IllegalArgumentException("The default key '" + options.defaultKey() + "' isn't a key: 1-" + MAX_KEY_LENGTH
                    + " printable ASCII characters other than space, '!' and '#'.");
        var supplied = options.httpClient();
        VaultHttp.checkRedirects(supplied, options.allowRedirects());

        this.timeout = options.timeout();
        this.timeoutNanos = VaultHttp.saturatedNanos(timeout);
        this.retryCount = options.retryCount();
        this.retryDelay = options.retryDelay();
        this.namespace = options.namespace();
        this.defaultKey = options.defaultKey();
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
     * Whether name is a secret's path: '/'-separated segments of ASCII letters, digits, '-', '_' and
     * '.', no segment "." or "..", at most {@link #MAX_SECRET_NAME_LENGTH} characters. A key to read
     * follows it in a lookup, after '#' (see {@link RemoteSecretCache#isValidKey}).
     */
    public static boolean isValidSecretName(String name) {
        return name != null && !name.isEmpty() && name.length() <= MAX_SECRET_NAME_LENGTH && VaultHttp.isValidPath(name);
    }

    /**
     * Releases the cache's connections by closing its own HttpClient, which waits for requests in
     * flight (each bounded by the timeout); a supplied HttpClient is left open. Cached secrets can
     * still be read afterwards, but a lookup that would read Vault fails with
     * IllegalStateException.
     */
    @Override
    public void close() {
        closed = true;
        if (ownsHttp)
            http.close();
    }

    @Override
    protected String defaultKey() {
        return defaultKey;
    }

    @Override
    protected boolean isValidName(String name) {
        return isValidSecretName(name);
    }

    @Override
    protected void fetch(String name, SecretValueSink value) {
        if (closed)
            throw new IllegalStateException("This HashiCorp Vault secret cache has been closed.");

        // Asked for once per fetch; a provider's failure is its own to retry, so isn't retried here.
        var protectedToken = getToken();
        // A failed attempt has handed nothing to value: the body is read whole before anything is
        // parsed out of it, and a parse failure isn't transient.
        VaultHttp.withRetries(retryCount, retryDelay, () -> closed, () -> {
            read(name, protectedToken, value);
            return null;
        }, HashiCorpVaultSecretCacheImpl::cancelled);
    }

    // The protected token the provider hands over, waited for within the timeout.
    private String getToken() {
        var future = tokenProvider.getTokenAsync();
        if (future == null)
            throw new IllegalStateException("The Vault token provider returned no token.");

        // A failure, never a cancellation: nobody cancelled this fetch.
        return VaultHttp.await(future, timeoutNanos,
                () -> new CompletionException(new TimeoutException("The Vault token provider returned no token within " + timeout + ".")),
                HashiCorpVaultSecretCacheImpl::cancelled);
    }

    // One attempt: one request, and Vault's whole response, within the attempt's timeout.
    private void read(String path, String protectedToken, SecretValueSink value) throws IOException, InterruptedException {
        var deadline = System.nanoTime() + timeoutNanos;
        VaultHttp.send(http, request(path, protectedToken), deadline, response -> {
            readResponse(path, response.statusCode(), response.body(), value);
            return null;
        }, () -> "Vault's response to the read of '" + path + "' took longer than " + timeout + ".");
    }

    // The request for path's secret, carrying the token protectedToken holds - refused unless the
    // cache's token protector protected it and it is a token (VaultHttp.withToken). That token's
    // String is referenced only by the request, so lives no longer than it, until collected.
    private HttpRequest request(String path, String protectedToken) {
        var builder = VaultHttp.newRequest(URI.create(readBase + path), timeout, namespace).GET();
        return VaultHttp.withToken(builder, tokenProtector, protectedToken).build();
    }

    private void readResponse(String path, int status, InputStream body, SecretValueSink value) throws IOException {
        if (status >= 200 && status < 300) {
            SecretJsonBody.captureKeys(body, value, dataPath);
            return;
        }

        // An error response holds no secret: read whole, for its errors and warnings.
        var bytes = body.readNBytes(ErrorResponseBody.MAX_BODY_LENGTH);
        var errors = ErrorResponseBody.readStrings(new ByteArrayInputStream(bytes), "errors");

        // Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
        // secret whose latest version is deleted, with its metadata and none. A 404 naming an error
        // (no such mount) or that isn't Vault's JSON (a proxy's page) is a failure. So is one warning
        // that the path is invalid for a versioned engine: the engine is KV version 2, read as
        // version 1, and every secret would otherwise read as missing.
        if (status == 404 && errors != null && errors.isEmpty()) {
            var mismatch = kvVersionMismatch(ErrorResponseBody.readStrings(new ByteArrayInputStream(bytes), "warnings"));
            if (mismatch != null)
                throw new VaultRequestException("Vault refused to read '" + path + "': HTTP 404: the engine is KV version 2, but this cache"
                        + " reads it as version 1; set the options' kvVersion to V2. Vault warned: " + mismatch, status);
            return;
        }

        var detail = errors != null && !errors.isEmpty() ? ": " + String.join("; ", errors) : "";
        throw new VaultRequestException("Vault refused to read '" + path + "': HTTP " + status + detail, status);
    }

    // The warning Vault gives for a KV version 1 read of a KV version 2 engine, or null.
    private static String kvVersionMismatch(List<String> warnings) {
        if (warnings != null)
            for (var warning : warnings)
                if (warning.contains(VERSIONED_ENGINE_WARNING))
                    return warning;
        return null;
    }

    private static CancellationException cancelled() {
        return new CancellationException("The read from Vault was abandoned: the thread fetching it was interrupted.");
    }

}
