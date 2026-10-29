package io.github.runsecure.hkdfguard.cache.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.cache.ErrorResponseBody;
import io.github.runsecure.hkdfguard.cache.RemoteSecretCache;
import io.github.runsecure.hkdfguard.cache.SecretJsonBody;
import io.github.runsecure.hkdfguard.cache.SecretNameMatching;
import io.github.runsecure.hkdfguard.cache.SecretValueSink;
import io.github.runsecure.hkdfguard.remote.VaultHttp;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.CharBuffer;
import java.time.Duration;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicBoolean;
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
 * reported missing. Any other answer (403 for a token that is invalid or not allowed to read the
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
 * timeout fails the fetch with a {@link CancellationException}. The token is handed over protected
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

    private static final String TOKEN_HEADER = "X-Vault-Token";

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
     *                                  isn't zero to 10 seconds; or the HttpClient follows
     *                                  redirects without allowRedirects
     */
    public HashiCorpVaultSecretCacheImpl(URI address, VaultTokenProvider tokenProvider, DataProtector tokenProtector, KeyRing keyRing,
            HashiCorpVaultSecretCacheOptions options, Logger logger) {
        super(keyRing, SecretNameMatching.EXACT, logger);
        this.tokenProvider = Objects.requireNonNull(tokenProvider, "tokenProvider");
        this.tokenProtector = Objects.requireNonNull(tokenProtector, "tokenProtector");
        if (options == null)
            options = HashiCorpVaultSecretCacheOptions.builder().build();
        var apiBase = VaultHttp.apiBase(address, "a token");

        if (!VaultHttp.isValidPath(options.mountPath()))
            throw new IllegalArgumentException("The mount path '" + options.mountPath() + "' isn't a Vault path.");
        if (!isValidKey(options.defaultKey()))
            throw new IllegalArgumentException("The default key '" + options.defaultKey() + "' isn't a key: 1-" + MAX_KEY_LENGTH
                    + " printable ASCII characters other than space, '!' and '#'.");
        if (options.namespace() != null && !VaultHttp.isValidPath(options.namespace()))
            throw new IllegalArgumentException("The namespace '" + options.namespace() + "' isn't a Vault path.");
        if (options.timeout().isNegative() || options.timeout().isZero())
            throw new IllegalArgumentException("The timeout must be positive; it is " + options.timeout() + ".");
        if (options.retryCount() < HashiCorpVaultSecretCacheOptions.MIN_RETRY_COUNT
                || options.retryCount() > HashiCorpVaultSecretCacheOptions.MAX_RETRY_COUNT)
            throw new IllegalArgumentException("The retry count must be " + HashiCorpVaultSecretCacheOptions.MIN_RETRY_COUNT + "-"
                    + HashiCorpVaultSecretCacheOptions.MAX_RETRY_COUNT + "; it is " + options.retryCount() + ".");
        if (options.retryDelay().isNegative() || options.retryDelay().compareTo(HashiCorpVaultSecretCacheOptions.MAX_RETRY_DELAY) > 0)
            throw new IllegalArgumentException("The retry delay must be zero to " + HashiCorpVaultSecretCacheOptions.MAX_RETRY_DELAY
                    + "; it is " + options.retryDelay() + ".");
        var supplied = options.httpClient();
        if (supplied != null && !options.allowRedirects() && supplied.followRedirects() != HttpClient.Redirect.NEVER)
            throw new IllegalArgumentException("The HttpClient follows redirects, which would send the Vault token wherever they point. "
                    + "Build it with followRedirects(HttpClient.Redirect.NEVER), or set allowRedirects if every redirect target may see the token.");

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

        // A redirect would carry X-Vault-Token to wherever it points. Vault's standbys forward
        // requests to the active node themselves, so a redirect is answered as an error instead.
        this.ownsHttp = supplied == null;
        this.http = supplied != null ? supplied : HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
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
     * The wait before retry number {@code retry} (0 for the first): baseDelay, doubled for each
     * retry before it, at most {@link HashiCorpVaultSecretCacheOptions#MAX_RETRY_DELAY} - plus
     * jitterMillis.
     */
    static Duration retryDelay(Duration baseDelay, int retry, int jitterMillis) {
        return VaultHttp.retryDelay(baseDelay, retry, jitterMillis, HashiCorpVaultSecretCacheOptions.MAX_RETRY_DELAY);
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
        for (var retry = 0; ; retry++) {
            RuntimeException failure;
            try {
                read(name, protectedToken, value);
                return;
            } catch (VaultRequestException e) {
                if (!e.isTransient())
                    throw e;
                failure = e;
            } catch (IOException e) {
                failure = new UncheckedIOException(e);
            } catch (UncheckedIOException e) {
                failure = e;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw cancelled();
            }

            // A body read that was interrupted fails as an IOException, the interrupt status set.
            if (Thread.currentThread().isInterrupted())
                throw cancelled();
            if (retry >= retryCount || closed)
                throw failure;

            // A failed attempt has handed nothing to value: the body is read whole before anything
            // is parsed out of it, and a parse failure isn't transient.
            try {
                Thread.sleep(retryDelay(retryDelay, retry, VaultHttp.jitterMillis()));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw cancelled();
            }
        }
    }

    // The protected token the provider hands over, waited for within the timeout.
    private String getToken() {
        var future = tokenProvider.getTokenAsync();
        if (future == null)
            throw new IllegalStateException("The Vault token provider returned no token.");

        return VaultHttp.await(future, timeoutNanos,
                () -> new CancellationException("The Vault token provider returned no token within " + timeout + "."),
                HashiCorpVaultSecretCacheImpl::cancelled);
    }

    // One attempt: one request, and Vault's whole response, within the attempt's timeout.
    private void read(String path, String protectedToken, SecretValueSink value) throws IOException, InterruptedException {
        var deadline = System.nanoTime() + timeoutNanos;
        var response = http.send(request(path, protectedToken), HttpResponse.BodyHandlers.ofInputStream());

        try (var body = response.body()) {
            // HttpRequest's timeout ends once the headers arrive; this one covers the whole body.
            var expired = new AtomicBoolean();
            var watchdog = VaultHttp.watchDeadline(deadline, body, expired);
            try {
                readResponse(path, response.statusCode(), body, value);
            } catch (IOException | UncheckedIOException e) {
                if (expired.get())
                    throw new HttpTimeoutException("Vault's response to the read of '" + path + "' took longer than " + timeout + ".");
                throw e;
            } finally {
                watchdog.interrupt();
            }
        }
    }

    // The request for path's secret, carrying the token protectedToken holds. That token's String
    // is referenced only by the request, so lives no longer than it, until collected.
    private HttpRequest request(String path, String protectedToken) {
        var builder = HttpRequest.newBuilder(URI.create(readBase + path))
                .timeout(timeout)
                .GET()
                .header("X-Vault-Request", "true");
        if (namespace != null)
            builder.header("X-Vault-Namespace", namespace);

        return builder.header(TOKEN_HEADER, decryptToken(protectedToken)).build();
    }

    private void readResponse(String path, int status, InputStream body, SecretValueSink value) throws IOException {
        if (status >= 200 && status < 300) {
            SecretJsonBody.captureKeys(body, value, dataPath);
            return;
        }

        var errors = ErrorResponseBody.readStrings(body, "errors");

        // Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
        // secret whose latest version is deleted, with its metadata and none. A 404 naming an error
        // (no such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
        if (status == 404 && errors != null && errors.isEmpty())
            return;

        var detail = errors != null && !errors.isEmpty() ? ": " + String.join("; ", errors) : "";
        throw new VaultRequestException("Vault refused to read '" + path + "': HTTP " + status + detail, status);
    }

    // The token protectedToken holds, as the String its header needs. Decrypted into a char array
    // zeroed before returning; refused unless it is protected by the token protector - it parses,
    // its key version is on the ring, and it authenticates under TOKEN_PURPOSE - and is a token.
    // The protector's exceptions aren't chained: a parser handed an unprotected token could quote it.
    private String decryptToken(String protectedToken) {
        if (protectedToken == null || protectedToken.isEmpty())
            throw new IllegalStateException("The Vault token provider returned no token.");

        int maxLength;
        try {
            maxLength = tokenProtector.getMaxDecryptedLength(protectedToken);
        } catch (IllegalArgumentException | CryptographicException | NoSuchElementException e) {
            throw notProtected();
        }
        if (maxLength < 0)
            throw notProtected();

        var chars = new char[maxLength];
        try {
            int length;
            try {
                length = tokenProtector.decrypt(protectedToken, chars);
            } catch (IllegalArgumentException | CryptographicException | NoSuchElementException e) {
                throw notProtected();
            }

            if (!VaultHttp.isValidToken(CharBuffer.wrap(chars, 0, length)))
                throw new IllegalStateException("The protected Vault token isn't a token: printable ASCII, with no spaces.");

            return new String(chars, 0, length);
        } finally {
            ArrayUtility.zeroMemory(chars);
        }
    }

    private static IllegalStateException notProtected() {
        return new IllegalStateException("The Vault token provider returned a token that isn't protected by the cache's token protector: "
                + "hand over tokenProtector.encrypt(token), never the token itself.");
    }

    private static CancellationException cancelled() {
        return new CancellationException("The read from Vault was abandoned: the thread fetching it was interrupted.");
    }

}
