package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.remote.JsonReader;
import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.net.ssl.SSLParameters;

/**
 * The rules every HkdfGuard request to Vault follows, for code that makes its own requests rather
 * than going through {@link VaultClient} - the HashiCorp Vault secret cache and transit key
 * wrapper, which read secrets and keys into arrays of their own: where requests may go, which
 * tokens and paths can be sent, how a token is decrypted for a request, how a request is sent and
 * its whole response bounded by a timeout, which failures are retried and how long to wait, and
 * what Vault's error responses say. Each caller keeps its own messages.
 */
public final class VaultHttp {
    private static final Logger LOG = LoggerFactory.getLogger(VaultHttp.class);

    /** The longest token a fixed-size token buffer holds, in characters: what a {@link VaultTokenSource} may supply. */
    public static final int MAX_TOKEN_LENGTH = 2048;

    /** The longest wait {@link #retryDelay} returns, jitter aside. */
    public static final Duration MAX_RETRY_DELAY = Duration.ofSeconds(10);

    /** The fewest retries {@link #checkSettings} allows. */
    public static final int MIN_RETRY_COUNT = 3;

    /** The most retries {@link #checkSettings} allows. */
    public static final int MAX_RETRY_COUNT = 10;

    /** The header a request's token goes in. */
    public static final String TOKEN_HEADER = "X-Vault-Token";

    private static final Pattern IPV4_LITERAL = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private VaultHttp() {
    }

    /**
     * /v1/ under Vault's address, refusing an address that would send what every request carries -
     * named by carried, e.g. "a token" - in the clear (http anywhere but loopback), or that holds
     * credentials, a query or a fragment. A path in the address is kept as a prefix (Vault behind a
     * reverse proxy).
     *
     * @throws NullPointerException     address is null
     * @throws IllegalArgumentException address isn't absolute, isn't https (or http on loopback), or
     *                                  holds credentials, a query or a fragment
     */
    public static String apiBase(URI address, String carried) {
        Objects.requireNonNull(address, "address");
        if (!address.isAbsolute() || address.isOpaque() || address.getHost() == null)
            throw new IllegalArgumentException("Vault's address '" + address + "' isn't absolute, e.g. https://vault.example.com:8200.");

        var scheme = address.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("https") && !(scheme.equals("http") && isLoopback(address.getHost())))
            throw new IllegalArgumentException("Vault's address '" + address + "' must be https; http is allowed only on a loopback "
                    + "address (a local Vault Agent or dev server), since every request carries " + carried + ".");
        if (address.getRawUserInfo() != null || address.getRawQuery() != null || address.getRawFragment() != null)
            throw new IllegalArgumentException("Vault's address '" + address + "' must not hold credentials, a query or a fragment.");

        return scheme + "://" + address.getRawAuthority() + trimTrailingSlashes(address.getRawPath()) + "/v1/";
    }

    /** path without the '/'s it ends in; "" for null. */
    static String trimTrailingSlashes(String path) {
        if (path == null)
            return "";

        var end = path.length();
        while (end > 0 && path.charAt(end - 1) == '/')
            end--;
        return path.substring(0, end);
    }

    /**
     * Whether host is localhost, or an IP literal on the loopback network. Only literals are parsed,
     * so no name is ever resolved.
     */
    static boolean isLoopback(String host) {
        if (host == null)
            return false;
        if (host.equalsIgnoreCase("localhost"))
            return true;
        if (!host.startsWith("[") && !IPV4_LITERAL.matcher(host).matches())
            return false;

        try {
            return InetAddress.getByName(host).isLoopbackAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /** Whether path is '/'-separated segments, each one {@link #isValidPathSegment}: a path that stays where it's put. */
    public static boolean isValidPath(String path) {
        if (path == null)
            return false;

        var start = 0;
        while (true) {
            var end = path.indexOf('/', start);
            if (!isValidSegment(path, start, end < 0 ? path.length() : end))
                return false;
            if (end < 0)
                return true;
            start = end + 1;
        }
    }

    /** Whether segment is ASCII letters, digits, '-', '_' and '.', and not empty, "." or "..". */
    public static boolean isValidPathSegment(String segment) {
        return segment != null && isValidSegment(segment, 0, segment.length());
    }

    /** Whether path[start, end) is one segment of ASCII letters, digits, '-', '_' and '.', other than "." and "..". */
    public static boolean isValidSegment(String path, int start, int end) {
        var length = end - start;
        if (length == 0 || (length == 1 && path.charAt(start) == '.') || (length == 2 && path.startsWith("..", start)))
            return false;

        for (var i = start; i < end; i++) {
            var c = path.charAt(i);
            var allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
            if (!allowed)
                return false;
        }
        return true;
    }

    /** Whether token can go in a header: non-empty printable ASCII, with no spaces. */
    public static boolean isValidToken(CharSequence token) {
        if (token.isEmpty())
            return false;

        for (var i = 0; i < token.length(); i++) {
            var c = token.charAt(i);
            if (c < '!' || c > '~')
                return false;
        }
        return true;
    }

    /**
     * The client to send requests to Vault with when the caller supplies none: no automatic
     * redirects, TLS 1.2 or later, a 30-second connect timeout. Close it when done.
     */
    public static HttpClient newHttpClient() {
        return newHttpClientBuilder().build();
    }

    /**
     * The client to send requests to Vault with: supplied when it isn't null, otherwise
     * {@link #newHttpClient()}'s, using tls's SSLContext when tls sets anything. Close the client
     * this creates when done. A client that skips certificate verification
     * ({@link VaultTlsOptions#insecureSkipVerify()}, VAULT_SKIP_VERIFY) is logged as a warning each
     * time one is created.
     *
     * @param tls null, or empty, for the JDK's defaults
     * @throws IllegalArgumentException supplied and TLS options are both given - TLS options can't be
     *                                  applied to a supplied client - or tls's certificates, keys or
     *                                  key stores can't be read
     */
    public static HttpClient httpClient(HttpClient supplied, VaultTlsOptions tls) {
        return httpClient(supplied, tls, LOG);
    }

    /** {@link #httpClient(HttpClient, VaultTlsOptions)}, warning logger: the tests'. */
    static HttpClient httpClient(HttpClient supplied, VaultTlsOptions tls, Logger logger) {
        var hasTls = tls != null && !tls.isEmpty();
        if (supplied != null) {
            if (hasTls)
                throw new IllegalArgumentException("TLS options can't be applied to a supplied HttpClient: give it its own SSLContext instead.");
            return supplied;
        }

        var builder = newHttpClientBuilder();
        if (hasTls) {
            if (tls.insecureSkipVerify())
                logger.warn("TLS certificate verification is off for HashiCorp Vault (insecureSkipVerify, or VAULT_SKIP_VERIFY): anyone between"
                        + " this process and Vault can read every token and secret sent. Use it only against a throwaway dev server.");
            builder.sslContext(tls.createSslContext());
        }
        return builder.build();
    }

    /** A builder for {@link #newHttpClient()}'s client, to add an SSLContext to. */
    static HttpClient.Builder newHttpClientBuilder() {
        var tls = new SSLParameters();
        tls.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
        // A redirect would carry X-Vault-Token to wherever it points: java.net.http drops only
        // Authorization, Cookie, Origin, Referer and Host when following one. Vault's standbys
        // forward requests to the active node themselves, so a redirect is answered as an error
        // unless the caller decides otherwise.
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .sslParameters(tls)
                .connectTimeout(Duration.ofSeconds(30));
    }

    /**
     * Checks the settings the secret cache and the transit key wrapper share: where the engine is
     * mounted, the namespace, each attempt's timeout, and how often and how soon to retry.
     *
     * @throws IllegalArgumentException the mount path or namespace (which may be null) isn't a Vault
     *                                  path; the timeout isn't positive; the retry count isn't
     *                                  {@link #MIN_RETRY_COUNT}-{@link #MAX_RETRY_COUNT}; or the retry
     *                                  delay isn't zero to {@link #MAX_RETRY_DELAY}
     */
    public static void checkSettings(String mountPath, String namespace, Duration timeout, int retryCount, Duration retryDelay) {
        if (!isValidPath(mountPath))
            throw new IllegalArgumentException("The mount path '" + mountPath + "' isn't a Vault path.");
        if (namespace != null && !isValidPath(namespace))
            throw new IllegalArgumentException("The namespace '" + namespace + "' isn't a Vault path.");
        if (timeout.isNegative() || timeout.isZero())
            throw new IllegalArgumentException("The timeout must be positive; it is " + timeout + ".");
        if (retryCount < MIN_RETRY_COUNT || retryCount > MAX_RETRY_COUNT)
            throw new IllegalArgumentException("The retry count must be " + MIN_RETRY_COUNT + "-" + MAX_RETRY_COUNT + "; it is " + retryCount + ".");
        if (retryDelay.isNegative() || retryDelay.compareTo(MAX_RETRY_DELAY) > 0)
            throw new IllegalArgumentException("The retry delay must be zero to " + MAX_RETRY_DELAY + "; it is " + retryDelay + ".");
    }

    /** Whether http follows redirects itself, which would send the token wherever they point. */
    public static boolean followsRedirects(HttpClient http) {
        return Objects.requireNonNull(http, "http").followRedirects() != HttpClient.Redirect.NEVER;
    }

    /**
     * Refuses a caller's HttpClient that follows redirects unless allowRedirects says every redirect
     * target may see the token; does nothing for null (the caller's own client).
     *
     * @throws IllegalArgumentException supplied follows redirects and allowRedirects is false
     */
    public static void checkRedirects(HttpClient supplied, boolean allowRedirects) {
        if (supplied != null && !allowRedirects && followsRedirects(supplied))
            throw new IllegalArgumentException("The HttpClient follows redirects, which would send the Vault token wherever they point. "
                    + "Build it with followRedirects(HttpClient.Redirect.NEVER), or set allowRedirects if every redirect target may see the token.");
    }

    /**
     * The token protectedToken holds, decrypted with tokenProtector into an array exactly its
     * length, which the caller zeroes once used. Refused unless it is protected by tokenProtector -
     * it parses, its key version is on the ring, and it authenticates under the protector's purpose
     * - and is a token. The protector's exceptions aren't chained: a parser handed an unprotected
     * token could quote it.
     *
     * @throws IllegalStateException protectedToken is empty, isn't protected by tokenProtector, or
     *                               doesn't hold a token
     */
    public static char[] decryptToken(DataProtector tokenProtector, String protectedToken) {
        Objects.requireNonNull(tokenProtector, "tokenProtector");
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

            if (!isValidToken(CharBuffer.wrap(chars, 0, length)))
                throw new IllegalStateException("The protected Vault token isn't a token: printable ASCII, with no spaces.");
            if (length == maxLength) {
                var token = chars;
                chars = null;
                return token;
            }

            var token = new char[length];
            System.arraycopy(chars, 0, token, 0, length);
            return token;
        } finally {
            ArrayUtility.zeroMemory(chars);
        }
    }

    private static IllegalStateException notProtected() {
        return new IllegalStateException("The Vault token provider returned a token that isn't protected by the token protector it was given: "
                + "hand over tokenProtector.encrypt(token), never the token itself.");
    }

    /**
     * The wait before retry number {@code retry} (0 for the first): baseDelay, doubled for each
     * retry before it, at most {@link #MAX_RETRY_DELAY} - plus jitterMillis, so callers that failed
     * together don't retry in lockstep.
     */
    public static Duration retryDelay(Duration baseDelay, int retry, int jitterMillis) {
        var backoff = retry >= 30 ? MAX_RETRY_DELAY : baseDelay.multipliedBy(1L << retry);
        return (backoff.compareTo(MAX_RETRY_DELAY) < 0 ? backoff : MAX_RETRY_DELAY).plusMillis(jitterMillis);
    }

    /**
     * 0-100 ms, the jitter each retry's wait adds. It spreads load, nothing more: no secret depends
     * on it, so a cryptographic generator gains nothing.
     */
    @SuppressWarnings("java:S2245")
    public static int jitterMillis() {
        return ThreadLocalRandom.current().nextInt(0, 101);
    }

    /**
     * Whether Vault may answer another attempt differently: 429 (rate limited) or a 5xx other than
     * 501 (Vault answers 503 while sealed or electing a leader).
     */
    public static boolean isTransientStatus(int statusCode) {
        return statusCode == 429 || (statusCode >= 500 && statusCode != 501);
    }

    /** One attempt at a request, for {@link #withRetries}. */
    @FunctionalInterface
    public interface Attempt<T> {
        T run() throws IOException, InterruptedException;
    }

    /**
     * Runs attempt until it succeeds, fails in a way another attempt wouldn't change, or has been
     * retried retryCount times, waiting {@link #retryDelay} between attempts. Transient: an
     * IOException (no answer, a connection lost mid-response, a timed-out attempt) or a
     * {@link VaultRequestException} that {@link VaultRequestException#isTransient() is}. Anything
     * else attempt throws propagates at once. closed is asked before each retry; once it's true, the
     * last failure is thrown rather than retried.
     *
     * @throws VaultRequestException the attempt's, not transient or the last
     * @throws UncheckedIOException  the last attempt's IOException, wrapped
     * @throws CancellationException cancelled's, when the thread is interrupted (whose status is set
     *                               again)
     */
    public static <T> T withRetries(int retryCount, Duration retryDelay, BooleanSupplier closed, Attempt<T> attempt,
            Supplier<CancellationException> cancelled) {
        for (var retry = 0; ; retry++) {
            RuntimeException failure;
            try {
                return attempt.run();
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
                throw cancelled.get();
            }

            // A body read that was interrupted fails as an IOException, the interrupt status set.
            if (Thread.currentThread().isInterrupted())
                throw cancelled.get();
            if (retry >= retryCount || closed.getAsBoolean())
                throw failure;

            try {
                Thread.sleep(retryDelay(retryDelay, retry, jitterMillis()));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw cancelled.get();
            }
        }
    }

    /** Reads a response whose body {@link #send} bounds by the deadline. */
    @FunctionalInterface
    public interface ResponseReader<T> {
        T read(HttpResponse<InputStream> response) throws IOException;
    }

    /**
     * Sends request and has reader read the response, its whole body included, by deadlineNanos (a
     * System.nanoTime()): HttpRequest's own timeout ends once the headers arrive, so the body is
     * closed under the reader if it runs past the deadline. The body is closed once reader returns.
     *
     * @throws HttpTimeoutException timedOut's message, when the body outran the deadline
     */
    public static <T> T send(HttpClient http, HttpRequest request, long deadlineNanos, ResponseReader<T> reader, Supplier<String> timedOut)
            throws IOException, InterruptedException {
        var response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        try (var body = response.body()) {
            var expired = new AtomicBoolean();
            var watchdog = watchDeadline(deadlineNanos, body, expired);
            try {
                return reader.read(response);
            } catch (IOException | UncheckedIOException e) {
                if (expired.get())
                    throw new HttpTimeoutException(timedOut.get());
                throw e;
            } finally {
                watchdog.interrupt();
            }
        }
    }

    /**
     * A request to uri carrying the headers every HkdfGuard request to Vault does: X-Vault-Request,
     * which a Vault Agent or proxy configured with require_request_header requires, and
     * X-Vault-Namespace unless namespace is null. The method, body and token are the caller's.
     *
     * @param timeout the request's timeout; null for none
     */
    public static HttpRequest.Builder newRequest(URI uri, Duration timeout, String namespace) {
        var builder = HttpRequest.newBuilder(uri).header("X-Vault-Request", "true");
        if (timeout != null)
            builder.timeout(timeout);
        if (namespace != null)
            builder.header("X-Vault-Namespace", namespace);
        return builder;
    }

    /**
     * Adds X-Vault-Token to builder, carrying the token protectedToken holds: decrypted into an
     * array zeroed at once ({@link #decryptToken}), and from there into the one String
     * java.net.http takes a header's value as, referenced only by this request.
     *
     * @throws IllegalStateException as {@link #decryptToken}
     */
    public static HttpRequest.Builder withToken(HttpRequest.Builder builder, DataProtector tokenProtector, String protectedToken) {
        var token = decryptToken(tokenProtector, protectedToken);
        try {
            return builder.header(TOKEN_HEADER, new String(token));
        } finally {
            ArrayUtility.zeroMemory(token);
        }
    }

    /**
     * A body publisher over body[0, length) itself. BodyPublishers.ofByteArray copies the array into
     * buffers of java.net.http's own on every send, which nothing zeroes; this hands over the array,
     * wrapped, so zeroing it reaches the bytes every attempt sent.
     */
    public static HttpRequest.BodyPublisher bodyPublisher(byte[] body, int length) {
        Objects.checkFromIndexSize(0, length, Objects.requireNonNull(body, "body").length);
        return new ArrayBodyPublisher(body, length);
    }

    /** duration in nanoseconds, or Long.MAX_VALUE for one too long to count in them. */
    public static long saturatedNanos(Duration duration) {
        try {
            return duration.toNanos();
        } catch (ArithmeticException e) {
            return Long.MAX_VALUE;
        }
    }

    /**
     * The result of future, waited for at most timeoutNanos; cancelled on a timeout or an interrupt
     * (which is restored). A failure is rethrown as it is when unchecked, an IOException as an
     * UncheckedIOException, anything else in a CompletionException.
     * <p>
     * A timeout is a failure, not a cancellation: timedOut supplies what is thrown, and must not be a
     * CancellationException, so that a caller counting failures (a refresh-failure policy) counts it.
     *
     * @throws RuntimeException      timedOut's, after the timeout
     * @throws CancellationException interrupted's, on an interrupt
     */
    public static <T> T await(Future<T> future, long timeoutNanos, Supplier<? extends RuntimeException> timedOut,
            Supplier<CancellationException> interrupted) {
        try {
            return future.get(timeoutNanos, TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw timedOut.get();
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw interrupted.get();
        } catch (ExecutionException e) {
            var cause = KeyWrapperFutures.unwrap(e);
            if (cause instanceof RuntimeException runtime)
                throw runtime;
            if (cause instanceof Error error)
                throw error;
            if (cause instanceof IOException io)
                throw new UncheckedIOException(io);
            throw new CompletionException(cause);
        }
    }

    /**
     * Runs work on a virtual thread of its own, named threadName, and returns at once; cancelling
     * the returned future interrupts that thread. What work throws fails the future as failure
     * turns it.
     *
     * @param abandoned run when work fails, or succeeds only after the future was cancelled, when
     *                  nobody is waiting for what it wrote any more; null for nothing
     */
    public static <T> CompletableFuture<T> runAsync(String threadName, Callable<T> work, Function<Throwable, ? extends Throwable> failure,
            Runnable abandoned) {
        var future = new CompletableFuture<T>();
        var thread = Thread.ofVirtual().name(threadName).unstarted(() -> {
            try {
                if (!future.complete(work.call()) && abandoned != null)
                    abandoned.run();
            } catch (Throwable e) {
                if (abandoned != null)
                    abandoned.run();
                future.completeExceptionally(failure.apply(e));
            }
        });
        future.whenComplete((value, error) -> {
            if (future.isCancelled())
                thread.interrupt();
        });
        thread.start();
        return future;
    }

    /**
     * Starts a virtual thread that, unless interrupted first, closes body once System.nanoTime()
     * passes deadlineNanos, setting expired before it does: HttpRequest's timeout ends once the
     * headers arrive, and this covers the rest of the response. Interrupt the thread it returns
     * once the body is read.
     */
    public static Thread watchDeadline(long deadlineNanos, InputStream body, AtomicBoolean expired) {
        return Thread.ofVirtual().name("hkdfguard-vault-deadline").start(() -> {
            try {
                Thread.sleep(Duration.ofNanos(Math.max(0, deadlineNanos - System.nanoTime())));
            } catch (InterruptedException e) {
                // The body was read in time; the thread ends either way.
                Thread.currentThread().interrupt();
                return;
            }
            expired.set(true);
            closeQuietly(body);
        });
    }

    /** Closes body, ignoring a failure: the read it ends fails anyway. */
    public static void closeQuietly(InputStream body) {
        try {
            body.close();
        } catch (IOException ignored) {
            // The read it ends fails anyway.
        }
    }

    /**
     * The errors Vault listed in an error response body[0, length): its "errors" array, a string as
     * its text and anything else as its JSON text; empty if the body is a JSON object without
     * errors; null if it isn't Vault's JSON - a proxy's page, say. An error response holds no
     * secret, so its errors may become Strings.
     */
    public static List<String> readErrors(byte[] body, int length) {
        var reader = new JsonReader(body, length);
        try {
            if (!reader.read() || reader.token() != Token.START_OBJECT)
                return null;

            List<String> found = List.of();
            while (reader.read() && reader.token() == Token.PROPERTY_NAME) {
                var isErrors = reader.valueTextEquals("errors");
                reader.read();
                if (!isErrors) {
                    reader.skip();
                } else if (reader.token() != Token.START_ARRAY) {
                    return null;
                } else {
                    var errors = new ArrayList<String>();
                    while (reader.read() && reader.token() != Token.END_ARRAY) {
                        var start = reader.tokenStart();
                        if (reader.token() == Token.STRING) {
                            errors.add(reader.getString());
                            continue;
                        }

                        reader.skip();
                        errors.add(new String(body, start, reader.bytesConsumed() - start, StandardCharsets.UTF_8));
                    }
                    found = List.copyOf(errors);
                }
            }

            // Anything after the object makes it not JSON.
            return reader.read() ? null : found;
        } catch (JsonReader.Malformed e) {
            return null;
        }
    }

    /**
     * " Bad Request" and the like, for the statuses Vault and the proxies in front of it answer
     * with; "" for any other. java.net.http doesn't report the reason phrase a server sent.
     */
    public static String reasonPhrase(int status) {
        return switch (status) {
            case 301 -> " Moved Permanently";
            case 302 -> " Found";
            case 303 -> " See Other";
            case 307 -> " Temporary Redirect";
            case 308 -> " Permanent Redirect";
            case 400 -> " Bad Request";
            case 401 -> " Unauthorized";
            case 403 -> " Forbidden";
            case 404 -> " Not Found";
            case 405 -> " Method Not Allowed";
            case 412 -> " Precondition Failed";
            case 429 -> " Too Many Requests";
            case 500 -> " Internal Server Error";
            case 501 -> " Not Implemented";
            case 502 -> " Bad Gateway";
            case 503 -> " Service Unavailable";
            case 504 -> " Gateway Timeout";
            default -> "";
        };
    }

    /**
     * Publishes a body straight from the array it wraps, so zeroing the array reaches the bytes
     * every attempt sent.
     */
    private static final class ArrayBodyPublisher implements HttpRequest.BodyPublisher {
        private final byte[] body;
        private final int length;

        ArrayBodyPublisher(byte[] body, int length) {
            this.body = body;
            this.length = length;
        }

        @Override
        public long contentLength() {
            return length;
        }

        @Override
        public void subscribe(Flow.Subscriber<? super ByteBuffer> subscriber) {
            var done = new AtomicBoolean();
            subscriber.onSubscribe(new Flow.Subscription() {
                @Override
                public void request(long n) {
                    if (!done.compareAndSet(false, true))
                        return;
                    if (n <= 0) {
                        subscriber.onError(new IllegalArgumentException("A subscriber must request at least one item; it requested " + n + "."));
                        return;
                    }
                    subscriber.onNext(ByteBuffer.wrap(body, 0, length));
                    subscriber.onComplete();
                }

                @Override
                public void cancel() {
                    done.set(true);
                }
            });
        }
    }
}
