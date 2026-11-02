package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A HashiCorp Vault client: a port of vault-client-go. Generic {@link #readAsync},
 * {@link #writeAsync}, {@link #listAsync} and {@link #deleteAsync} reach any path; the methods
 * generated from Vault's OpenAPI spec reach the endpoints generator.json names, typed, grouped as
 * {@link #auth()}, {@link #secrets()} and {@link #system()} ({@link VaultApis}).
 * <p>
 * Tokens are held only protected - encrypted by the client's token protector, a protector on a key
 * ring ({@code keyRing.createProtector(TOKEN_PURPOSE)}) - and supplied by a
 * {@link VaultTokenProvider}. A token is decrypted only as a request is sent, into a char array that
 * is zeroed at once. java.net.http takes a header's value only as a String, though, and a Java
 * String can't be zeroed: each attempt's token becomes one String, made for that request alone and
 * referenced by nothing once it has been sent, until the garbage collector reuses it. A token Vault
 * returns (a login's, a wrapping token) is protected straight from the response's bytes, so never
 * becomes a String. Request and response bodies are held in arrays that are zeroed after use; what a
 * generated model holds, though, is ordinary Strings.
 * <p>
 * Defaults are stricter than vault-client-go's: Vault's address must be https except on loopback,
 * and redirects - which would carry the token wherever they point - fail with
 * {@link VaultRedirectException} unless {@link VaultClientOptions#followRedirects()} is set.
 * Failures are retried as vault-client-go retries them ({@link VaultRetryOptions}).
 * <p>
 * Every request runs on a virtual thread of its own and returns at once, after its arguments are
 * checked; cancelling the returned future interrupts that thread, abandoning the request. The future
 * fails with {@link VaultResponseException} when Vault refuses the request, with
 * {@link VaultRedirectException} for a redirect it won't follow, with the IOException java.net.http
 * threw when Vault can't be reached, with {@link TimeoutException} when the request outlives
 * {@link VaultClientOptions#requestTimeout()}, and with {@link VaultJsonException} when the answer
 * isn't the JSON expected.
 * <p>
 * Thread-safe. Settings changed with the set and clear methods apply to requests started
 * afterwards. Close the client to release its connections.
 */
public final class VaultClient implements VaultApis, AutoCloseable {
    /**
     * The purpose to create the token protector with - {@code keyRing.createProtector(TOKEN_PURPOSE)}
     * - so a token protected for the client can't be decrypted as anything else, nor anything else as
     * it.
     */
    public static final String TOKEN_PURPOSE = "HkdfGuard.Integration.HashiCorpVault.Token";

    private static final String HEALTH_PATH = "/v1/sys/health";

    private final VaultClientOptions options;
    private final DataProtector tokenProtector;
    private final Logger logger;
    private final HttpClient http;
    private final boolean ownsHttp;
    private final AtomicBoolean closed;
    private final String baseAddress;
    private final VaultRetryOptions.RetryPolicy checkRetry;
    private final VaultRetryOptions.Backoff backoff;
    private final VaultReplication.StateCache replicationStates;
    private final Object modifiersLock = new Object();
    private volatile RequestModifiers modifiers;

    /**
     * A client of the Vault at https://127.0.0.1:8200, with the default options.
     *
     * @see #VaultClient(DataProtector, VaultClientOptions, Logger)
     */
    public VaultClient(DataProtector tokenProtector) {
        this(tokenProtector, null, null);
    }

    /**
     * A client logging to its own SLF4J logger.
     *
     * @see #VaultClient(DataProtector, VaultClientOptions, Logger)
     */
    public VaultClient(DataProtector tokenProtector, VaultClientOptions options) {
        this(tokenProtector, options, null);
    }

    /**
     * @param tokenProtector protects and decrypts tokens: a protector on the key ring,
     *                       {@code keyRing.createProtector(TOKEN_PURPOSE)}. Every token the client
     *                       is given must be protected by it.
     * @param options        how to reach Vault; null for the defaults (https://127.0.0.1:8200)
     * @param logger         where retries and followed redirects are logged (paths only, never a
     *                       query); null for the class's own SLF4J logger
     * @throws NullPointerException     tokenProtector is null
     * @throws IllegalArgumentException the address isn't https (or http on loopback, or with
     *                                  allowUnencryptedHttp), or holds credentials, a query or a
     *                                  fragment; the namespace can't be sent; the request timeout or a
     *                                  retry wait is negative; the HttpClient follows redirects, or is
     *                                  given together with TLS options; or a certificate can't be read
     */
    public VaultClient(DataProtector tokenProtector, VaultClientOptions options, Logger logger) {
        this.tokenProtector = Objects.requireNonNull(tokenProtector, "tokenProtector");
        if (options == null)
            options = VaultClientOptions.builder().build();
        this.baseAddress = baseAddress(options);
        if (options.requestTimeout().isNegative())
            throw new IllegalArgumentException("The request timeout must not be negative; it is " + options.requestTimeout() + ".");
        if (options.retry().retryWaitMin().isNegative() || options.retry().retryWaitMax().isNegative())
            throw new IllegalArgumentException("The retry waits must not be negative.");
        var ns = options.namespace();
        if (ns != null && !ns.isEmpty() && !isValidNamespace(ns))
            throw new IllegalArgumentException("The namespace '" + ns + "' contains non-printable characters.");
        var supplied = options.httpClient();
        if (supplied != null && VaultHttp.followsRedirects(supplied))
            throw new IllegalArgumentException("The HttpClient follows redirects, which would send the Vault token wherever they point. "
                    + "Build it with followRedirects(HttpClient.Redirect.NEVER): the client follows redirects itself when followRedirects is set.");
        this.http = VaultHttp.httpClient(supplied, options.tls());

        this.options = options;
        this.logger = logger != null ? logger : LoggerFactory.getLogger(VaultClient.class);
        this.ownsHttp = supplied == null;
        this.closed = new AtomicBoolean();
        var retry = options.retry();
        this.checkRetry = retry.checkRetry() != null ? retry.checkRetry() : VaultRetryOptions::defaultRetryPolicy;
        this.backoff = retry.backoff() != null ? retry.backoff() : VaultRetryOptions::linearJitterBackoff;
        this.replicationStates = options.enforceReadYourWritesConsistency() ? new VaultReplication.StateCache(List.of()) : null;
        this.modifiers = RequestModifiers.initial(VaultUserAgent.VALUE, options.token(), ns == null || ns.isEmpty() ? null : ns);
    }

    // A copy: the same connections, a copy of the settings and replication states.
    private VaultClient(VaultClient original) {
        options = original.options;
        tokenProtector = original.tokenProtector;
        logger = original.logger;
        http = original.http;
        ownsHttp = false;
        closed = original.closed;
        baseAddress = original.baseAddress;
        checkRetry = original.checkRetry;
        backoff = original.backoff;
        replicationStates = original.replicationStates == null ? null : original.replicationStates.copy();
        modifiers = original.modifiers;
    }

    /** The options the client was created with. */
    public VaultClientOptions options() {
        return options;
    }

    /**
     * A client with this one's options, settings (token, namespace, headers, callbacks...) and
     * replication states, which then change independently. It shares this client's connections:
     * closing it does nothing, and it can't be used once this client is closed.
     */
    public VaultClient copy() {
        return new VaultClient(this);
    }

    /**
     * Releases the client's connections by closing its own HttpClient, which waits for requests in
     * flight; a supplied HttpClient is left open. A copy's close does nothing. A request started
     * afterwards fails with IllegalStateException.
     */
    @Override
    public void close() {
        if (!ownsHttp)
            return;
        closed.set(true);
        http.close();
    }

    /**
     * token, protected by the client's token protector: for {@link #setToken(VaultTokenProvider)} or
     * {@link VaultRequestOptions#token()}. token is read-only, so it isn't cleared here: pass a
     * {@code CharBuffer.wrap(char[])} to keep the token out of String, and clear the array once this
     * returns.
     *
     * @throws IllegalArgumentException token is empty, or isn't printable ASCII without spaces
     */
    public StaticVaultToken protectToken(CharSequence token) {
        return StaticVaultToken.protect(tokenProtector, token);
    }

    /** Makes every later request with token, unless the request sets its own; see https://developer.hashicorp.com/vault/docs/concepts/tokens. */
    public void setToken(VaultTokenProvider token) {
        Objects.requireNonNull(token, "token");
        update(m -> m.withToken(token));
    }

    /**
     * Protects token and makes every later request with it; see {@link #protectToken}.
     *
     * @throws IllegalArgumentException token is empty, or isn't printable ASCII without spaces
     */
    public void setToken(CharSequence token) {
        setToken(protectToken(token));
    }

    /** Makes later requests without a token, unless they set their own. */
    public void clearToken() {
        update(m -> m.withToken(null));
    }

    /**
     * Makes every later request in ns, unless the request sets its own; empty for none. See
     * https://developer.hashicorp.com/vault/docs/enterprise/namespaces.
     *
     * @throws IllegalArgumentException ns contains non-printable characters
     */
    public void setNamespace(String ns) {
        Objects.requireNonNull(ns, "ns");
        if (!ns.isEmpty() && !isValidNamespace(ns))
            throw new IllegalArgumentException("The namespace '" + ns + "' contains non-printable characters.");
        update(m -> m.withNamespace(ns.isEmpty() ? null : ns));
    }

    /** Makes later requests in no namespace, unless they set their own. */
    public void clearNamespace() {
        update(m -> m.withNamespace(null));
    }

    /**
     * Sends credentials (X-Vault-MFA) with every later request; see
     * https://developer.hashicorp.com/vault/docs/auth/login-mfa.
     *
     * @throws IllegalArgumentException a credential is empty or not printable ASCII
     */
    public void setMfaCredentials(String... credentials) {
        Objects.requireNonNull(credentials, "credentials");
        var copy = List.of(credentials);
        RequestModifiers.validateMfaCredentials(copy);
        update(m -> m.withMfaCredentials(copy));
    }

    /** Stops sending MFA credentials. */
    public void clearMfaCredentials() {
        update(m -> m.withMfaCredentials(List.of()));
    }

    /**
     * Asks Vault to wrap every later response for ttl (X-Vault-Wrap-TTL); zero to stop. See
     * https://developer.hashicorp.com/vault/docs/concepts/response-wrapping.
     *
     * @throws IllegalArgumentException ttl is negative
     */
    public void setResponseWrapping(Duration ttl) {
        Objects.requireNonNull(ttl, "ttl");
        if (ttl.isNegative())
            throw new IllegalArgumentException("The wrapping TTL must not be negative; it is " + ttl + ".");
        update(m -> m.withResponseWrappingTtl(ttl));
    }

    /** Stops asking Vault to wrap responses. */
    public void clearResponseWrapping() {
        update(m -> m.withResponseWrappingTtl(Duration.ZERO));
    }

    /**
     * Adds headers to every later request, replacing those set before; names starting X-Vault- are
     * refused.
     *
     * @throws IllegalArgumentException a header has no name, is named X-Vault-*, or can't be sent
     */
    public void setCustomHeaders(Map<String, List<String>> headers) {
        Objects.requireNonNull(headers, "headers");
        var copy = RequestModifiers.copyHeaders(headers);
        RequestModifiers.validateCustomHeaders(copy);
        update(m -> m.withCustomHeaders(copy));
    }

    /** Stops adding custom headers. */
    public void clearCustomHeaders() {
        update(m -> m.withCustomHeaders(Map.of()));
    }

    /** Calls callbacks with each attempt's request before it's sent (without its token), replacing those set before. */
    public void setRequestCallbacks(VaultRequestCallback... callbacks) {
        var copy = List.of(Objects.requireNonNull(callbacks, "callbacks"));
        update(m -> m.withRequestCallbacks(copy));
    }

    /** Stops calling request callbacks. */
    public void clearRequestCallbacks() {
        update(m -> m.withRequestCallbacks(List.of()));
    }

    /** Calls callbacks once Vault has answered each request, replacing those set before. */
    public void setResponseCallbacks(VaultResponseCallback... callbacks) {
        var copy = List.of(Objects.requireNonNull(callbacks, "callbacks"));
        update(m -> m.withResponseCallbacks(copy));
    }

    /** Stops calling response callbacks. */
    public void clearResponseCallbacks() {
        update(m -> m.withResponseCallbacks(List.of()));
    }

    /**
     * Sends a forwarding header with every later request (Vault Enterprise): X-Vault-Forward for
     * ALWAYS, X-Vault-Inconsistent for INCONSISTENT, none for NONE. See
     * https://developer.hashicorp.com/vault/docs/enterprise/consistency#vault-1-7-mitigations.
     */
    public void setReplicationForwardingMode(ReplicationForwardingMode mode) {
        Objects.requireNonNull(mode, "mode");
        update(m -> m.withReplicationForwardingMode(mode));
    }

    /** Stops sending a forwarding header. */
    public void clearReplicationForwardingMode() {
        update(m -> m.withReplicationForwardingMode(ReplicationForwardingMode.NONE));
    }

    /**
     * Whether failure - or the first {@link VaultResponseException} or {@link VaultRedirectException}
     * among its causes, through any CompletionException - is Vault answering with status.
     */
    public static boolean isErrorStatus(Throwable failure, int status) {
        for (var e = failure; e != null; e = e.getCause()) {
            if (e instanceof VaultResponseException || e instanceof VaultRedirectException)
                return ((VaultRequestException) e).statusCode() == status;
        }
        return false;
    }

    // --- Generic requests --------------------------------------------------------------------

    /**
     * Reads the value at path (GET /v1/path).
     *
     * @param path the path under /v1/, with or without that prefix
     * @return completes with Vault's response; null if it has no body
     */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> readAsync(String path) {
        return readAsync(path, null);
    }

    /** As {@link #readAsync(String)}, with settings for this request. */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> readAsync(String path, VaultRequestOptions options) {
        Objects.requireNonNull(path, "path");
        return sendAsync("GET", v1Path(path), null, queryParameters(options), options, JsonValue::readJsonMap);
    }

    /**
     * Reads path (GET /v1/path) and returns Vault's response as it is: not parsed, not checked for an
     * error status, and not bound by {@link VaultClientOptions#requestTimeout()} - for a large or
     * streamed body. Close it once read.
     */
    public CompletableFuture<VaultRawResponse> readRawAsync(String path) {
        return readRawAsync(path, null);
    }

    /** As {@link #readRawAsync(String)}, with settings for this request. */
    public CompletableFuture<VaultRawResponse> readRawAsync(String path, VaultRequestOptions options) {
        Objects.requireNonNull(path, "path");
        var modifiers = this.modifiers.merge(options);
        var query = queryParameters(options);
        return run(() -> {
            var sent = sendCore("GET", v1Path(path), null, 0, query, modifiers, Long.MAX_VALUE, false);
            return new VaultRawResponse(sent.response().statusCode(), sent.response().headers(), sent.response().body());
        });
    }

    /** Writes body, as a JSON object, to path (POST /v1/path). Its values are written as {@link JsonWriter#value} writes them. */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> writeAsync(String path, Map<String, ?> body) {
        return writeAsync(path, body, null);
    }

    /** As {@link #writeAsync(String, Map)}, with settings for this request. */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> writeAsync(String path, Map<String, ?> body, VaultRequestOptions options) {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(body, "body");
        return sendAsync("POST", v1Path(path), body, queryParameters(options), options, JsonValue::readJsonMap);
    }

    /**
     * Writes body as it is to path (POST /v1/path). body is sent from the array itself, every
     * attempt: leave it unchanged until the future completes, then clear it if it holds a secret.
     */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> writeFromBytesAsync(String path, byte[] body) {
        return writeFromBytesAsync(path, body, null);
    }

    /** As {@link #writeFromBytesAsync(String, byte[])}, with settings for this request. */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> writeFromBytesAsync(String path, byte[] body, VaultRequestOptions options) {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(body, "body");
        var modifiers = this.modifiers.merge(options);
        var query = queryParameters(options);
        return run(() -> send("POST", v1Path(path), body, body.length, query, modifiers, JsonValue::readJsonMap));
    }

    /**
     * Writes what body holds to path (POST /v1/path). It's read whole first - into an array zeroed
     * afterwards - so a retry can send it again. body isn't closed.
     */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> writeFromStreamAsync(String path, InputStream body) {
        return writeFromStreamAsync(path, body, null);
    }

    /** As {@link #writeFromStreamAsync(String, InputStream)}, with settings for this request. */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> writeFromStreamAsync(String path, InputStream body, VaultRequestOptions options) {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(body, "body");
        var modifiers = this.modifiers.merge(options);
        var query = queryParameters(options);
        return run(() -> {
            try (var buffer = new SecureBuffer()) {
                buffer.readFrom(body);
                return send("POST", v1Path(path), buffer.array(), buffer.length(), query, modifiers, JsonValue::readJsonMap);
            }
        });
    }

    /** Lists the keys at path (GET /v1/path?list=true). */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> listAsync(String path) {
        return listAsync(path, null);
    }

    /** As {@link #listAsync(String)}, with settings for this request. */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> listAsync(String path, VaultRequestOptions options) {
        Objects.requireNonNull(path, "path");
        var query = queryParameters(options);
        query.add(Map.entry("list", "true"));
        return sendAsync("GET", v1Path(path), null, query, options, JsonValue::readJsonMap);
    }

    /** Deletes the value at path (DELETE /v1/path). */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> deleteAsync(String path) {
        return deleteAsync(path, null);
    }

    /** As {@link #deleteAsync(String)}, with settings for this request. */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> deleteAsync(String path, VaultRequestOptions options) {
        Objects.requireNonNull(path, "path");
        return sendAsync("DELETE", v1Path(path), null, queryParameters(options), options, JsonValue::readJsonMap);
    }

    /**
     * The response wrappingToken wraps (PUT /v1/sys/wrapping/unwrap, made with that token), its data
     * as JSON values; see https://developer.hashicorp.com/vault/docs/concepts/response-wrapping.
     *
     * @param wrappingToken the wrapping token - {@link VaultResponseWrapInfo#token()}, or one
     *                      protected with {@link #protectToken}
     * @return completes with the response that was wrapped; fails with
     *         {@link VaultResponseException} when Vault refuses the token: unknown, expired or
     *         already used
     */
    public CompletableFuture<VaultResponse<Map<String, JsonValue>>> unwrapAsync(VaultTokenProvider wrappingToken) {
        return unwrapAsync(wrappingToken, JsonValue::readJsonMap, null);
    }

    /**
     * As {@link #unwrapAsync(VaultTokenProvider)}, its data read with reader - the static fromJson
     * of the model the wrapped method returns, e.g. {@code KvV2ReadResponse::fromJson}.
     */
    public <T> CompletableFuture<VaultResponse<T>> unwrapAsync(VaultTokenProvider wrappingToken, Function<JsonValue, T> reader) {
        return unwrapAsync(wrappingToken, reader, null);
    }

    /** As {@link #unwrapAsync(VaultTokenProvider, Function)}, with settings for this request; its token is replaced by wrappingToken. */
    public <T> CompletableFuture<VaultResponse<T>> unwrapAsync(VaultTokenProvider wrappingToken, Function<JsonValue, T> reader,
            VaultRequestOptions options) {
        Objects.requireNonNull(wrappingToken, "wrappingToken");
        Objects.requireNonNull(reader, "reader");
        var withToken = (options != null ? options.toBuilder() : VaultRequestOptions.builder()).token(wrappingToken).build();
        return sendAsync("PUT", "/v1/sys/wrapping/unwrap", null, null, withToken, reader);
    }

    // --- For the generated methods -----------------------------------------------------------

    /** options' mount path, leading and trailing '/' trimmed, or defaultMountPath. */
    static String mountPathOr(VaultRequestOptions options, String defaultMountPath) {
        if (options == null || options.mountPath() == null)
            return defaultMountPath;

        var mountPath = options.mountPath();
        var start = 0;
        var end = mountPath.length();
        while (start < end && mountPath.charAt(start) == '/')
            start++;
        while (end > start && mountPath.charAt(end - 1) == '/')
            end--;
        return start == end ? defaultMountPath : mountPath.substring(start, end);
    }

    /** value as one path segment: everything but A-Z, a-z, 0-9, '-', '_', '.' and '~' percent-encoded as UTF-8, '/' included. */
    static String escapePathSegment(String value) {
        var bytes = value.getBytes(StandardCharsets.UTF_8);
        var escaped = new StringBuilder(bytes.length);
        for (var b : bytes) {
            var c = (char) (b & 0xFF);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
                escaped.append(c);
            else
                escaped.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16))).append(Character.toUpperCase(Character.forDigit(c & 0xF, 16)));
        }
        return escaped.toString();
    }

    /** options' query parameters, in a fresh list to add the endpoint's own to. */
    static List<Map.Entry<String, String>> queryParameters(VaultRequestOptions options) {
        return options == null ? new ArrayList<>() : new ArrayList<>(options.queryParameters());
    }

    static String formatQueryValue(String value) {
        return value;
    }

    static String formatQueryValue(boolean value) {
        return value ? "true" : "false";
    }

    static String formatQueryValue(int value) {
        return Integer.toString(value);
    }

    static String formatQueryValue(long value) {
        return Long.toString(value);
    }

    /**
     * Sends a request - body, if any, as JSON - and reads Vault's response into a
     * {@link VaultResponse}; completes with null if it has no body. The generated methods all come here.
     */
    <T> CompletableFuture<VaultResponse<T>> sendAsync(String method, String path, Object body, List<Map.Entry<String, String>> query,
            VaultRequestOptions options, Function<JsonValue, T> reader) {
        var modifiers = this.modifiers.merge(options);
        // Written before this returns, so a model the caller changes afterwards isn't half-sent.
        var json = body == null ? null : new SecureBuffer();
        if (json != null) {
            try {
                new JsonWriter(json).value(body);
            } catch (RuntimeException e) {
                json.close();
                throw e;
            }
        }

        return run(() -> {
            try {
                return json == null
                        ? send(method, path, null, 0, query, modifiers, reader)
                        : send(method, path, json.array(), json.length(), query, modifiers, reader);
            } finally {
                if (json != null)
                    json.close();
            }
        });
    }

    /** Whether value can go in a header: printable ASCII, spaces allowed. */
    static boolean isValidNamespace(String value) {
        for (var i = 0; i < value.length(); i++) {
            var c = value.charAt(i);
            if (c < ' ' || c > '~')
                return false;
        }
        return true;
    }

    /** path under /v1/, whether or not it starts with "/", "v1/" or "/v1/" already. */
    static String v1Path(String path) {
        if (path.startsWith("/v1/"))
            return path;
        if (path.startsWith("v1/"))
            return "/" + path;
        if (path.startsWith("/"))
            return "/v1" + path;
        return "/v1/" + path;
    }

    // --- Sending -----------------------------------------------------------------------------

    // The request's deadline passed: the future fails with a TimeoutException naming it.
    private static final class DeadlineExceeded extends RuntimeException {
        private static final long serialVersionUID = 1L;

        DeadlineExceeded(String message) {
            super(message, null, false, false);
        }
    }

    // Runs work on a virtual thread of its own, which cancelling the returned future interrupts.
    private static <T> CompletableFuture<T> run(Callable<T> work) {
        return VaultHttp.runAsync("hkdfguard-vault-client", work, VaultClient::failure, null);
    }

    // What a request's failure fails its future with.
    private static Throwable failure(Throwable e) {
        if (e instanceof DeadlineExceeded)
            return new TimeoutException(e.getMessage());
        if (e instanceof InterruptedException)
            return cancelled();
        if (e instanceof UncheckedIOException io)
            return io.getCause();
        return e;
    }

    // One request within the request timeout: sent, its whole body read, and parsed.
    private <T> VaultResponse<T> send(String method, String path, byte[] body, int bodyLength, List<Map.Entry<String, String>> query,
            RequestModifiers modifiers, Function<JsonValue, T> reader) throws IOException, InterruptedException {
        var timeout = options.requestTimeout();
        var hasDeadline = !timeout.isZero();
        var deadline = hasDeadline ? System.nanoTime() + VaultHttp.saturatedNanos(timeout) : Long.MAX_VALUE;
        var timedOut = "Vault didn't answer " + method + " " + path + " within " + timeout + ".";

        var sent = sendCore(method, path, body, bodyLength, query, modifiers, deadline, hasDeadline);
        var response = sent.response();
        try (var stream = response.body(); var content = new SecureBuffer(response.headers().firstValueAsLong("Content-Length").orElse(0))) {
            var expired = new AtomicBoolean();
            var watchdog = hasDeadline ? VaultHttp.watchDeadline(deadline, stream, expired) : null;
            try {
                content.readFrom(stream);
            } catch (IOException e) {
                if (expired.get())
                    throw new DeadlineExceeded(timedOut);
                throw e;
            } finally {
                if (watchdog != null)
                    watchdog.interrupt();
            }

            // sys/health answers 429, 472, 473, 501 and 503 with the health status itself.
            var status = response.statusCode();
            if ((status < 200 || status > 399) && !path.equals(HEALTH_PATH))
                throw VaultResponseException.create(status, content.array(), content.length(), sent.request().method(), sent.request().uri());

            return VaultResponseReader.read(content.array(), content.length(), tokenProtector, reader);
        }
    }

    private record Sent(HttpRequest request, HttpResponse<InputStream> response) {
    }

    // Sends the request, retrying and following a redirect as configured, and calls the response
    // callbacks. The body of the response it returns is unread; the caller closes it. The request it
    // returns is the one Vault answered, without its token.
    private Sent sendCore(String method, String path, byte[] body, int bodyLength, List<Map.Entry<String, String>> query,
            RequestModifiers modifiers, long deadline, boolean hasDeadline) throws IOException, InterruptedException {
        if (closed.get())
            throw new IllegalStateException("This Vault client has been closed.");

        var uri = URI.create(baseAddress + path + queryString(query));
        var timedOut = "Vault didn't answer " + method + " " + path + " within " + options.requestTimeout() + ".";

        var limiter = options.rateLimiter();
        if (limiter != null && !limiter.acquire(hasDeadline ? deadline - System.nanoTime() : Long.MAX_VALUE))
            throw new DeadlineExceeded(timedOut);

        var states = replicationStates == null ? List.<String>of() : replicationStates.snapshot();

        // Asked for once per request; a provider's failure is its own to retry, so isn't retried here.
        String protectedToken = null;
        if (modifiers.token() != null) {
            var future = modifiers.token().getTokenAsync();
            if (future == null)
                throw new IllegalStateException("The Vault token provider returned no future.");
            protectedToken = VaultHttp.await(future, hasDeadline ? Math.max(0, deadline - System.nanoTime()) : Long.MAX_VALUE,
                    () -> new DeadlineExceeded(timedOut), VaultClient::cancelled);
            if (protectedToken == null || protectedToken.isEmpty())
                throw new IllegalStateException("The Vault token provider returned no token.");
        }

        var redirects = 1;
        while (true) {
            var sent = sendWithRetries(method, uri, path, body, bodyLength, modifiers, states, protectedToken, deadline, hasDeadline, timedOut);
            var response = sent.response();
            URI target;
            try {
                target = redirectTarget(response, sent.request(), redirects);
            } catch (RuntimeException e) {
                VaultHttp.closeQuietly(response.body());
                throw e;
            }
            if (target == null) {
                for (var callback : modifiers.responseCallbacks())
                    callback.onResponse(sent.request(), response.statusCode(), response.headers());
                if (replicationStates != null)
                    replicationStates.record(response.headers());
                return sent;
            }

            redirects--;
            logger.atInfo().addKeyValue("hkdfguard.event_id", 2)
                    .log("Vault redirected {} {} to {}; following it.", method, path, withoutQuery(target));
            VaultHttp.closeQuietly(response.body());
            uri = target;
        }
    }

    // Where a redirect response says to go, if following it is allowed; null if response isn't one.
    private URI redirectTarget(HttpResponse<InputStream> response, HttpRequest request, int redirects) {
        var status = response.statusCode();
        if (status != 301 && status != 302 && status != 307)
            return null;

        var from = request.uri();
        var header = response.headers().firstValue("Location");
        URI location;
        try {
            location = header.map(from::resolve).orElse(null);
        } catch (IllegalArgumentException e) {
            location = null;
        }
        if (location == null)
            throw new VaultRedirectException(status, "could not read the redirect location", null, request.method(), from);

        if (!options.followRedirects())
            throw new VaultRedirectException(status, "redirects are disabled", location, request.method(), from);
        if (redirects <= 0)
            throw new VaultRedirectException(status, "at most one redirect is allowed", location, request.method(), from);

        var scheme = location.getScheme() == null ? "" : location.getScheme().toLowerCase(Locale.ROOT);
        if (from.getScheme().equalsIgnoreCase("https") && !scheme.equals("https"))
            throw new VaultRedirectException(status, "the redirect would cause a protocol downgrade", location, request.method(), from);
        if (!scheme.equals("https") && !(scheme.equals("http") && (VaultHttp.isLoopback(location.getHost()) || options.allowUnencryptedHttp())))
            throw new VaultRedirectException(status, "the redirect would send the token over unencrypted http", location, request.method(), from);

        return location;
    }

    // One request, sent until it succeeds, fails in a way not worth retrying, or runs out of retries.
    private Sent sendWithRetries(String method, URI uri, String path, byte[] body, int bodyLength, RequestModifiers modifiers,
            List<String> states, String protectedToken, long deadline, boolean hasDeadline, String timedOut)
            throws IOException, InterruptedException {
        var retry = options.retry();
        for (var attempt = 0; ; attempt++) {
            var builder = createRequest(method, uri, body, bodyLength, modifiers, states, deadline, hasDeadline, timedOut);
            for (var callback : modifiers.requestCallbacks())
                callback.onRequest(builder);
            var described = builder.copy().build();

            HttpResponse<InputStream> response = null;
            IOException failure = null;
            try {
                response = sendOnce(builder, protectedToken);
            } catch (IOException e) {
                if (hasDeadline && System.nanoTime() - deadline >= 0)
                    throw new DeadlineExceeded(timedOut);
                // A send that was interrupted fails as an IOException, the interrupt status set.
                if (Thread.currentThread().isInterrupted())
                    throw new InterruptedException();
                if (attempt >= retry.retryMax() || !checkRetry.shouldRetry(0, e))
                    throw e;
                failure = e;
            }

            if (failure == null && (attempt >= retry.retryMax() || !checkRetry.shouldRetry(response.statusCode(), null)))
                return new Sent(described, response);

            var status = response == null ? 0 : response.statusCode();
            var delay = backoff.delay(retry.retryWaitMin(), retry.retryWaitMax(), attempt, status);
            if (delay == null || delay.isNegative())
                delay = Duration.ZERO;
            if (response != null)
                VaultHttp.closeQuietly(response.body());
            if (hasDeadline && VaultHttp.saturatedNanos(delay) >= deadline - System.nanoTime())
                throw new DeadlineExceeded(timedOut);

            logger.atWarn().addKeyValue("hkdfguard.event_id", 1).log("Vault request {} {} failed ({}); retry {} of {} in {}.", method, path,
                    failure != null ? failure.toString() : status + VaultHttp.reasonPhrase(status), attempt + 1, retry.retryMax(), delay);
            Thread.sleep(delay);
        }
    }

    // Sends the request with the token, if any, in its header (VaultHttp.withToken).
    private HttpResponse<InputStream> sendOnce(HttpRequest.Builder builder, String protectedToken) throws IOException, InterruptedException {
        if (protectedToken != null)
            VaultHttp.withToken(builder, tokenProtector, protectedToken);
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
    }

    // A request carrying the client's headers, as vault-client-go's newRequest builds it; the token
    // is added only as it's sent.
    private HttpRequest.Builder createRequest(String method, URI uri, byte[] body, int bodyLength, RequestModifiers modifiers,
            List<String> states, long deadline, boolean hasDeadline, String timedOut) {
        Duration timeout = null;
        if (hasDeadline) {
            var remaining = deadline - System.nanoTime();
            if (remaining <= 0)
                throw new DeadlineExceeded(timedOut);
            timeout = Duration.ofNanos(remaining);
        }
        var builder = VaultHttp.newRequest(uri, timeout, modifiers.namespace())
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : VaultHttp.bodyPublisher(body, bodyLength));

        var contentType = false;
        for (var header : modifiers.customHeaders().entrySet()) {
            contentType |= header.getKey().equalsIgnoreCase("Content-Type");
            for (var value : header.getValue())
                builder.header(header.getKey(), value);
        }
        if (body != null && !contentType)
            builder.header("Content-Type", "application/json");

        if (modifiers.userAgent() != null)
            builder.setHeader("User-Agent", modifiers.userAgent());

        for (var credential : modifiers.mfaCredentials())
            builder.header("X-Vault-MFA", credential);
        if (modifiers.responseWrappingTtl().compareTo(Duration.ZERO) > 0)
            builder.header("X-Vault-Wrap-TTL", GoDuration.format(modifiers.responseWrappingTtl()));

        switch (modifiers.replicationForwardingMode()) {
            case ALWAYS -> builder.header("X-Vault-Forward", "active-node");
            case INCONSISTENT -> builder.header("X-Vault-Inconsistent", "forward-active-node");
            case NONE -> {
                // No forwarding header.
            }
        }

        for (var state : states)
            builder.header(VaultReplication.INDEX_HEADER, state);
        return builder;
    }

    private void update(UnaryOperator<RequestModifiers> change) {
        synchronized (modifiersLock) {
            modifiers = change.apply(modifiers);
        }
    }

    // query, sorted by name (values of one name keep their order) as Go's url.Values.Encode sorts it.
    private static String queryString(List<Map.Entry<String, String>> query) {
        if (query == null || query.isEmpty())
            return "";

        var sorted = new ArrayList<>(query);
        sorted.sort(Comparator.comparing(Map.Entry::getKey));
        var result = new StringBuilder("?");
        for (var parameter : sorted) {
            if (result.length() > 1)
                result.append('&');
            result.append(escapePathSegment(parameter.getKey())).append('=').append(escapePathSegment(parameter.getValue()));
        }
        return result.toString();
    }

    // scheme://host[:port][/prefix] with no trailing '/', to put /v1/... after. Refuses an address
    // that would send tokens in the clear (http anywhere but loopback, unless allowed) or that
    // carries credentials, a query or a fragment.
    private static String baseAddress(VaultClientOptions options) {
        var address = options.address();
        var scheme = address.getScheme() == null ? "" : address.getScheme().toLowerCase(Locale.ROOT);
        if (scheme.equals("unix"))
            throw new IllegalArgumentException("Vault's address '" + address + "' is a unix socket, which java.net.http can't connect to: "
                    + "reach Vault (or its agent) over https, or http on loopback.");
        if (!address.isAbsolute() || address.isOpaque() || address.getHost() == null)
            throw new IllegalArgumentException("Vault's address '" + address + "' isn't absolute, e.g. https://vault.example.com:8200.");
        if (!scheme.equals("https") && !(scheme.equals("http") && (VaultHttp.isLoopback(address.getHost()) || options.allowUnencryptedHttp())))
            throw new IllegalArgumentException("Vault's address '" + address + "' must be https; http is allowed only on a loopback address "
                    + "(a local Vault Agent or dev server), or with allowUnencryptedHttp, since every request carries a token.");
        if (address.getRawUserInfo() != null || address.getRawQuery() != null || address.getRawFragment() != null)
            throw new IllegalArgumentException("Vault's address '" + address + "' must not hold credentials, a query or a fragment.");

        return scheme + "://" + address.getRawAuthority() + VaultHttp.trimTrailingSlashes(address.getRawPath());
    }

    private static String withoutQuery(URI uri) {
        return uri.getScheme() + "://" + uri.getRawAuthority() + (uri.getRawPath() == null ? "" : uri.getRawPath());
    }

    private static CancellationException cancelled() {
        return new CancellationException("The Vault request was abandoned: the thread making it was interrupted.");
    }
}
