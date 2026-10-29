package io.github.runsecure.hkdfguard.remote;

import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * The rules the HashiCorp Vault cache and key wrapper share for talking to Vault's HTTP API: which
 * addresses, paths and tokens are accepted, how long to wait between retries, and how a token
 * future and a response body are bounded by a timeout. Each caller keeps its own messages.
 */
public final class VaultHttp {
    private static final Pattern IPV4_LITERAL = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private VaultHttp() {
    }

    /**
     * /v1/ under Vault's address, refusing an address that would send what every request carries -
     * named by carried, e.g. "a token" - in the clear (http anywhere but loopback), or that holds
     * credentials, a query or a fragment.
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

        var path = address.getRawPath() == null ? "" : address.getRawPath();
        var end = path.length();
        while (end > 0 && path.charAt(end - 1) == '/')
            end--;
        return scheme + "://" + address.getRawAuthority() + path.substring(0, end) + "/v1/";
    }

    // localhost, or an IP literal on the loopback network. Only literals are parsed, so no name is
    // ever resolved.
    private static boolean isLoopback(String host) {
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

    /** '/'-separated segments, none empty, "." or "..": a path that stays where it's put. */
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
     * The wait before retry number {@code retry} (0 for the first): baseDelay, doubled for each
     * retry before it, at most maxDelay - plus jitterMillis.
     */
    public static Duration retryDelay(Duration baseDelay, int retry, int jitterMillis, Duration maxDelay) {
        var backoff = retry >= 30 ? maxDelay : baseDelay.multipliedBy(1L << retry);
        return (backoff.compareTo(maxDelay) < 0 ? backoff : maxDelay).plusMillis(jitterMillis);
    }

    /**
     * 0-100 ms, the jitter each retry's wait adds, so callers that failed together don't retry in
     * lockstep. It spreads load, nothing more: no secret depends on it, so a cryptographic
     * generator gains nothing.
     */
    @SuppressWarnings("java:S2245")
    public static int jitterMillis() {
        return ThreadLocalRandom.current().nextInt(0, 101);
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
     *
     * @throws CancellationException timedOut's, after the timeout; interrupted's, on an interrupt
     */
    public static <T> T await(Future<T> future, long timeoutNanos, Supplier<CancellationException> timedOut,
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
}
