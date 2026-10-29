package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.LocalKeyGeneration;
import io.github.runsecure.hkdfguard.abstractions.Utf8Utility;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.remote.JsonReader;
import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import io.github.runsecure.hkdfguard.remote.VaultHttp;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import io.github.runsecure.hkdfguard.securefile.TrustedKeyFile;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Protects (encrypt) and reveals (decrypt) a DEK under one key in a HashiCorp Vault transit secrets
 * engine, and generates fresh DEKs with datakey/wrapped - so on that path the plaintext DEK never
 * leaves Vault. The KEK never enters this process; every call is a request to Vault's HTTP API,
 * authorized by the token's policy and recorded in Vault's audit log. A wrapped DEK is Vault's
 * ciphertext as it returns it, "vault:v{version}:{base64}", in ASCII - byte for byte the .NET
 * {@code HashiCorpVaultTransitKeyWrapper}'s, so a key file made by either is read by the other,
 * given the same key and context.
 * <p>
 * The key is pinned by its path: every request names it, and a ciphertext carries only its key
 * version, never its key, so a key file wrapped under another transit key fails to authenticate
 * rather than being revealed. Vault's key rotation (transit/keys/{name}/rotate) keeps the name and
 * is transparent here: new DEKs are wrapped under the latest version, and older ones still reveal
 * while their version is at or above the key's min_decryption_version. The key must be an AEAD key
 * that isn't derived - aes256-gcm96 (Vault's default), aes128-gcm96 or chacha20-poly1305.
 * <p>
 * The context, if any, is bound into every wrapped DEK as Vault's associated_data (AAD): decrypt
 * fails unless it is presented again exactly. datakey/wrapped ignores associated_data, so with a
 * context {@link #generateAndWrapAsync} generates the DEK here and wraps it with encrypt instead -
 * the plaintext DEK then does cross the network to Vault, as on {@link #wrapAsync}. A response whose
 * warnings say Vault ignored a parameter (a Vault too old for associated_data) is refused, so a
 * context is never silently dropped. Vault's audit log HMACs request fields by default, but the
 * context isn't a secret and must not hold one.
 * <p>
 * Key files are read only from where an untrusted account can't have written or replaced them (see
 * {@link #readKeyFileAsync} and {@link KeyFileTrust}). Pinning the key stops a key file wrapped
 * under another key; this stops one wrapped under this key by anyone whose policy allows encrypt,
 * which would otherwise choose the DEK new data is encrypted under.
 * <p>
 * Plaintext key bytes this class owns are zeroed once used, and none ever becomes a String: the
 * request body encrypt is sent (the DEK, base64-encoded), handed to java.net.http by a body
 * publisher that wraps the array rather than copying it, and zeroed once every attempt is done; the
 * response body, read straight off java.net.http's stream into an array of this class's own; the
 * value taken out of it (parsed by hand over bytes); and the DEK decoded out of that. The token is
 * copied by its {@link VaultTokenSource} into a char array this class owns and zeroes. java.net.http
 * takes a header's value only as a String, though, and a Java String can't be zeroed: each
 * request's token becomes one String, made for that request alone and referenced by nothing once it
 * has been sent, which stays in memory until the garbage collector reuses it. What can't be zeroed
 * is below java.net.http's API: its header buffers, its response stream's buffers, HTTP/2 framing,
 * TLS encryption and decryption, and the socket's reads and writes.
 * <p>
 * Requests go to /v1/ under Vault's address, which must be https except on loopback; the wrapper's
 * own HttpClient follows no redirects, which would carry the token elsewhere. A request that fails
 * transiently - no answer, a connection lost mid-response, a timed-out attempt, 429 or a 5xx other
 * than 501 - is retried (see {@link HashiCorpVaultTransitKeyWrapperOptions#retryCount()}). Each call
 * runs on a virtual thread of its own and returns at once, after its arguments are checked (and, for
 * wrapAsync, the plaintext encoded into the request body); cancelling the returned future interrupts
 * that thread, abandoning the request or the wait between retries. Argument errors throw from the
 * call itself; everything else - a Vault refusal, an unreachable Vault, an answer that isn't
 * Vault's, a token source's failure, a revealed key that doesn't fit - completes the future
 * exceptionally. Close the wrapper to release its connections.
 */
public final class HashiCorpVaultTransitKeyWrapperImpl implements KeyWrapper, AutoCloseable {
    /** The length of the DEK {@link #generateAndWrapAsync} generates: 32 bytes (AES-256). */
    public static final int GENERATED_KEY_LENGTH = 32;

    /**
     * The largest plaintext {@link #wrapAsync} accepts, in bytes: its ciphertext still fits
     * {@link WrappedKeyLimits#MAX_BYTES}.
     */
    public static final int MAX_PLAINTEXT_LENGTH = 256;

    /** The longest context, in UTF-8 bytes. */
    public static final int MAX_CONTEXT_LENGTH = 1024;

    /** The longest key name. */
    public static final int MAX_KEY_NAME_LENGTH = 128;

    /** The longest token a {@link VaultTokenSource} may supply, in characters. */
    public static final int MAX_TOKEN_LENGTH = 2048;

    /** The largest response read from Vault, in bytes; a transit answer is well under 1 KB. */
    static final int MAX_RESPONSE_LENGTH = 16 * 1024;

    private static final String TOKEN_HEADER = "X-Vault-Token";

    private static final byte[] BASE64_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".getBytes(StandardCharsets.US_ASCII);

    // Asks for a 256-bit key: GENERATED_KEY_LENGTH bytes.
    private static final byte[] DATA_KEY_BODY = ascii("{\"bits\":256}");

    private static final byte[] PLAINTEXT_PREFIX = ascii("{\"plaintext\":\"");

    private static final byte[] CIPHERTEXT_PREFIX = ascii("{\"ciphertext\":\"");

    private static final byte[] CIPHERTEXT_START = ascii("vault:v");

    private final HttpClient http;
    private final boolean ownsHttp;
    private final VaultTokenSource tokenSource;
    private final String keyName;
    private final URI encryptUri;
    private final URI decryptUri;
    private final URI dataKeyUri;
    private final boolean hasContext;
    // Closes every encrypt and decrypt body: the closing quote of its value, the context if any, and
    // the closing brace.
    private final byte[] bodySuffix;
    private final String namespace;
    private final Duration timeout;
    private final long timeoutNanos;
    private final int retryCount;
    private final Duration retryDelay;
    private final KeyFileTrust keyFileTrust;
    private volatile boolean closed;

    /**
     * A wrapper binding no context, over the engine at "transit", reading key files only
     * administrators can have written ({@link KeyFileTrust#ADMINISTRATORS_ONLY}).
     *
     * @see #HashiCorpVaultTransitKeyWrapperImpl(URI, String, VaultTokenSource, String, KeyFileTrust, HashiCorpVaultTransitKeyWrapperOptions)
     */
    public HashiCorpVaultTransitKeyWrapperImpl(URI address, String keyName, VaultTokenSource tokenSource) {
        this(address, keyName, tokenSource, null, null, null);
    }

    /**
     * A wrapper over the engine at "transit", reading key files only administrators can have written
     * ({@link KeyFileTrust#ADMINISTRATORS_ONLY}).
     *
     * @see #HashiCorpVaultTransitKeyWrapperImpl(URI, String, VaultTokenSource, String, KeyFileTrust, HashiCorpVaultTransitKeyWrapperOptions)
     */
    public HashiCorpVaultTransitKeyWrapperImpl(URI address, String keyName, VaultTokenSource tokenSource, String context) {
        this(address, keyName, tokenSource, context, null, null);
    }

    /**
     * A wrapper over the engine at "transit".
     *
     * @see #HashiCorpVaultTransitKeyWrapperImpl(URI, String, VaultTokenSource, String, KeyFileTrust, HashiCorpVaultTransitKeyWrapperOptions)
     */
    public HashiCorpVaultTransitKeyWrapperImpl(URI address, String keyName, VaultTokenSource tokenSource, String context,
            KeyFileTrust keyFileTrust) {
        this(address, keyName, tokenSource, context, keyFileTrust, null);
    }

    /**
     * @param address      Vault's address, e.g. https://vault.example.com:8200 - the same value as
     *                     VAULT_ADDR. Must be https, except on a loopback address (a local Vault
     *                     Agent or dev server). A path, if any, is kept as a prefix (Vault behind a
     *                     reverse proxy).
     * @param keyName      the transit key that wraps every DEK, e.g. "myapp-kek"
     * @param tokenSource  supplies the token every request is made with
     * @param context      bound into every wrapped DEK as associated_data and required again to
     *                     reveal it; null or empty binds none. Not secret.
     * @param keyFileTrust who besides the operating system's administrators may have written a key
     *                     file {@link #readKeyFileAsync} reads; null trusts administrators only
     *                     ({@link KeyFileTrust#ADMINISTRATORS_ONLY})
     * @param options      the transit engine called and how to reach it; null for the engine at
     *                     "transit"
     * @throws NullPointerException     address, keyName or tokenSource is null
     * @throws IllegalArgumentException address isn't https (or http on loopback), or holds
     *                                  credentials, a query or a fragment; keyName isn't a key name;
     *                                  the context holds an unpaired surrogate or is over
     *                                  {@link #MAX_CONTEXT_LENGTH} bytes; the mount path or
     *                                  namespace isn't one; the timeout isn't positive, the retry
     *                                  count isn't 3-10 or the retry delay isn't zero to 10 seconds;
     *                                  or the HttpClient follows redirects without allowRedirects
     */
    public HashiCorpVaultTransitKeyWrapperImpl(URI address, String keyName, VaultTokenSource tokenSource, String context,
            KeyFileTrust keyFileTrust, HashiCorpVaultTransitKeyWrapperOptions options) {
        Objects.requireNonNull(keyName, "keyName");
        this.tokenSource = Objects.requireNonNull(tokenSource, "tokenSource");
        if (options == null)
            options = HashiCorpVaultTransitKeyWrapperOptions.builder().build();
        var apiBase = VaultHttp.apiBase(address, "a token and DEKs");

        if (keyName.length() > MAX_KEY_NAME_LENGTH || !VaultHttp.isValidSegment(keyName, 0, keyName.length()))
            throw new IllegalArgumentException("The key name '" + keyName + "' isn't one: 1-" + MAX_KEY_NAME_LENGTH
                    + " ASCII letters, digits, '-', '_' and '.', and not \".\" or \"..\".");
        if (!VaultHttp.isValidPath(options.mountPath()))
            throw new IllegalArgumentException("The mount path '" + options.mountPath() + "' isn't a Vault path.");
        if (options.namespace() != null && !VaultHttp.isValidPath(options.namespace()))
            throw new IllegalArgumentException("The namespace '" + options.namespace() + "' isn't a Vault path.");
        if (options.timeout().isNegative() || options.timeout().isZero())
            throw new IllegalArgumentException("The timeout must be positive; it is " + options.timeout() + ".");
        if (options.retryCount() < HashiCorpVaultTransitKeyWrapperOptions.MIN_RETRY_COUNT
                || options.retryCount() > HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_COUNT)
            throw new IllegalArgumentException("The retry count must be " + HashiCorpVaultTransitKeyWrapperOptions.MIN_RETRY_COUNT + "-"
                    + HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_COUNT + "; it is " + options.retryCount() + ".");
        if (options.retryDelay().isNegative() || options.retryDelay().compareTo(HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_DELAY) > 0)
            throw new IllegalArgumentException("The retry delay must be zero to " + HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_DELAY
                    + "; it is " + options.retryDelay() + ".");
        var supplied = options.httpClient();
        if (supplied != null && !options.allowRedirects() && supplied.followRedirects() != HttpClient.Redirect.NEVER)
            throw new IllegalArgumentException("The HttpClient follows redirects, which would send the Vault token wherever they point. "
                    + "Build it with followRedirects(HttpClient.Redirect.NEVER), or set allowRedirects if every redirect target may see the token.");

        var contextBytes = encodeContext(context);
        if (contextBytes.length > MAX_CONTEXT_LENGTH)
            throw new IllegalArgumentException("The context is " + contextBytes.length + " bytes in UTF-8; at most "
                    + MAX_CONTEXT_LENGTH + " are allowed.");

        this.keyName = keyName;
        this.encryptUri = URI.create(apiBase + options.mountPath() + "/encrypt/" + keyName);
        this.decryptUri = URI.create(apiBase + options.mountPath() + "/decrypt/" + keyName);
        this.dataKeyUri = URI.create(apiBase + options.mountPath() + "/datakey/wrapped/" + keyName);
        // Vault treats an empty associated_data as none, so an empty context is none too.
        this.hasContext = contextBytes.length > 0;
        if (hasContext) {
            var prefix = ascii("\",\"associated_data\":\"");
            var suffix = new byte[prefix.length + base64Length(contextBytes.length) + 2];
            System.arraycopy(prefix, 0, suffix, 0, prefix.length);
            var length = encodeBase64(contextBytes, contextBytes.length, suffix, prefix.length);
            suffix[length] = '"';
            suffix[length + 1] = '}';
            this.bodySuffix = suffix;
        } else {
            this.bodySuffix = ascii("\"}");
        }
        this.namespace = options.namespace();
        this.timeout = options.timeout();
        this.timeoutNanos = VaultHttp.saturatedNanos(timeout);
        this.retryCount = options.retryCount();
        this.retryDelay = options.retryDelay();
        this.keyFileTrust = keyFileTrust != null ? keyFileTrust : KeyFileTrust.ADMINISTRATORS_ONLY;

        // A redirect would carry X-Vault-Token to wherever it points. Vault's standbys forward
        // requests to the active node themselves, so a redirect is answered as an error instead.
        this.ownsHttp = supplied == null;
        this.http = supplied != null ? supplied : HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    }

    /**
     * Releases the wrapper's connections by closing its own HttpClient, which waits for requests in
     * flight (each bounded by the timeout); a supplied HttpClient is left open. A call made
     * afterwards fails with IllegalStateException.
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
     * @return completes with the number of bytes written to result; fails with a
     *         {@link CryptographicException} when Vault refused the request (a
     *         {@link VaultRequestException} is the cause) or could not be reached (the
     *         {@link IOException} is the cause), or returned no ciphertext; with an
     *         {@link IllegalArgumentException} when result is too small for the wrapped DEK; with an
     *         {@link IllegalStateException} when the token source supplied no token, or one that
     *         isn't a token; or as the token source failed
     * @throws NullPointerException     plaintext or result is null
     * @throws IllegalArgumentException plaintext is empty or over {@link #MAX_PLAINTEXT_LENGTH} bytes
     */
    @Override
    public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(result, "result");
        if (plaintext.length == 0 || plaintext.length > MAX_PLAINTEXT_LENGTH)
            throw new IllegalArgumentException("Vault transit wraps 1-" + MAX_PLAINTEXT_LENGTH + " bytes here; got " + plaintext.length + ".");

        // Encoded before this returns, so the caller may zero plaintext at once; the body is zeroed
        // once every attempt is done.
        var body = writeBody(PLAINTEXT_PREFIX, plaintext, true);
        return run(() -> {
            try {
                return readAnswer(post("wrap", encryptUri, body), "wrap", result, false);
            } finally {
                ArrayUtility.zeroMemory(body);
            }
        }, null);
    }

    /**
     * {@inheritDoc}
     *
     * @return completes with the number of bytes written to result; fails with a
     *         {@link CryptographicException} when wrapped is empty, over
     *         {@link WrappedKeyLimits#MAX_BYTES} or isn't a Vault ciphertext, or Vault refused it -
     *         tampered with, wrapped under another key or under a different context, or its key
     *         version is below min_decryption_version (a {@link VaultRequestException} is the cause)
     *         - or could not be reached (the {@link IOException} is the cause); with an
     *         {@link IllegalArgumentException} when result is too small for the revealed key; with
     *         an {@link IllegalStateException} when the token source supplied no token, or one that
     *         isn't a token; or as the token source failed. On any failure after Vault is called,
     *         result is zeroed.
     * @throws NullPointerException wrapped or result is null
     */
    @Override
    public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
        Objects.requireNonNull(wrapped, "wrapped");
        Objects.requireNonNull(result, "result");
        // Refused locally: no ciphertext Vault produces is outside these bounds, and one that is
        // Vault's ciphertext needs no escaping to go in the request body.
        if (wrapped.length == 0 || wrapped.length > WrappedKeyLimits.MAX_BYTES)
            return CompletableFuture.failedFuture(new CryptographicException(
                    "A wrapped DEK is 1-" + WrappedKeyLimits.MAX_BYTES + " bytes; got " + wrapped.length + "."));
        if (!isVaultCiphertext(wrapped, wrapped.length))
            return CompletableFuture.failedFuture(new CryptographicException(
                    "A wrapped DEK is a Vault transit ciphertext, vault:v{version}:{base64}; this isn't one."));

        var body = writeBody(CIPHERTEXT_PREFIX, wrapped, false);
        return run(() -> readAnswer(post("unwrap", decryptUri, body), "unwrap", result, true), result);
    }

    /**
     * Generates a fresh {@link #GENERATED_KEY_LENGTH}-byte DEK wrapped under the key. Without a
     * context Vault generates it and returns it wrapped only (datakey/wrapped), so the plaintext DEK
     * never leaves Vault on this call. With a context - which datakey/wrapped would ignore - it is
     * generated here and wrapped with encrypt, then zeroed.
     *
     * @param result the wrapped key
     * @return as {@link #wrapAsync}
     * @throws NullPointerException result is null
     */
    @Override
    public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
        Objects.requireNonNull(result, "result");
        // wrapAsync encodes the DEK into its request body before it returns, so it can be zeroed
        // straight away.
        if (hasContext)
            return LocalKeyGeneration.generateAndWrap(this, GENERATED_KEY_LENGTH, result);

        return run(() -> readAnswer(post("generate-and-wrap", dataKeyUri, DATA_KEY_BODY), "generate-and-wrap", result, false), null);
    }

    /**
     * Reads a key file this wrapper wrote, still wrapped, refusing one that an account other than
     * the operating system's administrators and the {@link KeyFileTrust} given at construction could
     * have written or replaced - the Java equivalent of the native library's checks
     * ({@link TrustedKeyFile}). On Windows the file must be on a local fixed drive, reached through
     * real folders (no symbolic link, junction or substituted drive), and it and every folder above
     * it must be owned by, and modifiable only by, trusted principals. On Linux and macOS it and
     * every directory above it must be owned by root or a trusted user and writable by nobody else
     * (by its group only if that group is trusted), and only symbolic links a trusted user owns are
     * followed. It is also refused if it is empty, over {@link WrappedKeyLimits#MAX_BYTES}, or looks
     * like an unwrapped key. The file is read on the calling thread; no Vault call is made.
     *
     * @param path the key file's path
     * @return completes with the file's contents, still wrapped; fails with a
     *         {@link java.nio.file.NoSuchFileException} (the file doesn't exist), a
     *         {@link java.nio.file.AccessDeniedException} (this account may not read the file, or it
     *         isn't somewhere only trusted principals can modify), an
     *         {@link io.github.runsecure.hkdfguard.abstractions.InvalidKeyFileException} (the file is
     *         empty, too long, or holds what looks like an unwrapped key), another
     *         {@link java.io.IOException} (the file can't be read, or another process has it open
     *         for writing), or an {@link IllegalArgumentException} (the {@link KeyFileTrust} names a
     *         principal that can't be trusted)
     * @throws NullPointerException path is null
     */
    @Override
    public CompletableFuture<byte[]> readKeyFileAsync(Path path) {
        return TrustedKeyFile.readAsync(path, keyFileTrust);
    }

    /** Whether value[0, length) is a transit ciphertext as Vault writes it: vault:v{version}:{base64}. */
    static boolean isVaultCiphertext(byte[] value, int length) {
        if (length < CIPHERTEXT_START.length || !Arrays.equals(value, 0, CIPHERTEXT_START.length, CIPHERTEXT_START, 0, CIPHERTEXT_START.length))
            return false;

        var i = CIPHERTEXT_START.length;
        while (i < length && value[i] >= '0' && value[i] <= '9')
            i++;
        var digits = i - CIPHERTEXT_START.length;
        if (digits == 0 || digits > 10 || i >= length || value[i] != ':' || i + 1 >= length)
            return false;

        for (i++; i < length; i++) {
            if (base64Value(value[i]) < 0 && value[i] != '=')
                return false;
        }
        return true;
    }

    /**
     * The wait before retry number {@code retry} (0 for the first): baseDelay, doubled for each
     * retry before it, at most {@link HashiCorpVaultTransitKeyWrapperOptions#MAX_RETRY_DELAY} - plus
     * jitterMillis.
     */
    static Duration retryDelay(Duration baseDelay, int retry, int jitterMillis) {
        return VaultHttp.retryDelay(baseDelay, retry, jitterMillis, HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_DELAY);
    }

    // Runs work on a virtual thread of its own, which cancelling the returned future interrupts.
    // zeroOnFailure, if any, is zeroed when the work fails - or succeeds only after the future was
    // cancelled, when the caller is no longer waiting for what it wrote there.
    private static CompletableFuture<Integer> run(Callable<Integer> work, byte[] zeroOnFailure) {
        var future = new CompletableFuture<Integer>();
        var thread = Thread.ofVirtual().name("hkdfguard-vault-transit").unstarted(() -> {
            try {
                var written = work.call();
                if (!future.complete(written) && zeroOnFailure != null)
                    ArrayUtility.zeroMemory(zeroOnFailure);
            } catch (Throwable e) {
                if (zeroOnFailure != null)
                    ArrayUtility.zeroMemory(zeroOnFailure);
                future.completeExceptionally(e);
            }
        });
        future.whenComplete((value, error) -> {
            if (future.isCancelled())
                thread.interrupt();
        });
        thread.start();
        return future;
    }

    // prefix, then value (base64-encoded if encode), then the suffix: a whole encrypt or decrypt
    // body, exactly as long as it needs to be.
    private byte[] writeBody(byte[] prefix, byte[] value, boolean encode) {
        var body = new byte[prefix.length + (encode ? base64Length(value.length) : value.length) + bodySuffix.length];
        System.arraycopy(prefix, 0, body, 0, prefix.length);
        int length;
        if (encode) {
            length = encodeBase64(value, value.length, body, prefix.length);
        } else {
            System.arraycopy(value, 0, body, prefix.length, value.length);
            length = prefix.length + value.length;
        }

        System.arraycopy(bodySuffix, 0, body, length, bodySuffix.length);
        return body;
    }

    // Posts body to uri and returns Vault's successful answer, in an array the caller zeroes. The
    // token is asked for once; a request that fails transiently is retried. Vault's refusals, and
    // failures to reach it once the retries are spent, become CryptographicException.
    private Answer post(String operation, URI uri, byte[] body) {
        if (closed)
            throw new IllegalStateException("This HashiCorp Vault transit key wrapper has been closed.");

        var token = new char[MAX_TOKEN_LENGTH];
        try {
            // A source's failure is its own to retry, so isn't retried here, and propagates as it is.
            var tokenLength = copyToken(token);
            for (var retry = 0; ; retry++) {
                Exception failure;
                try {
                    return send(uri, body, token, tokenLength);
                } catch (VaultRequestException e) {
                    if (!e.isTransient())
                        throw failed(operation, e);
                    failure = e;
                } catch (IOException e) {
                    failure = e;
                } catch (UncheckedIOException e) {
                    failure = e.getCause();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw cancelled();
                }

                // A body read that was interrupted fails as an IOException, the interrupt status set.
                if (Thread.currentThread().isInterrupted())
                    throw cancelled();
                if (retry >= retryCount || closed)
                    throw failed(operation, failure);

                try {
                    Thread.sleep(retryDelay(retryDelay, retry, VaultHttp.jitterMillis()));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw cancelled();
                }
            }
        } finally {
            ArrayUtility.zeroMemory(token);
        }
    }

    // Has the token source copy the token into token, waited for within the timeout; returns its
    // length. Refused unless it is a token that fits.
    private int copyToken(char[] token) {
        var future = tokenSource.copyTokenAsync(token);
        if (future == null)
            throw new IllegalStateException("The Vault token source returned no future.");

        Integer length = VaultHttp.await(future, timeoutNanos,
                () -> new CancellationException("The Vault token source supplied no token within " + timeout + "."),
                HashiCorpVaultTransitKeyWrapperImpl::cancelled);

        if (length == null || length <= 0 || length > token.length || !VaultHttp.isValidToken(CharBuffer.wrap(token, 0, length)))
            throw new IllegalStateException("The Vault token source supplied no token, or one that isn't a token: printable ASCII, with no spaces.");
        return length;
    }

    // One attempt: one request, and Vault's whole response, within the attempt's timeout. A
    // successful response is returned in an array the caller zeroes; any other is thrown as a
    // VaultRequestException carrying Vault's status and errors.
    private Answer send(URI uri, byte[] body, char[] token, int tokenLength) throws IOException, InterruptedException {
        var deadline = System.nanoTime() + timeoutNanos;
        var builder = HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .POST(new ArrayBodyPublisher(body))
                .header("Content-Type", "application/json")
                .header("X-Vault-Request", "true");
        if (namespace != null)
            builder.header("X-Vault-Namespace", namespace);

        // The one String the token becomes: java.net.http takes a header's value only as one. It is
        // referenced only by this request, so lives no longer than it, until collected.
        var request = builder.header(TOKEN_HEADER, new String(token, 0, tokenLength)).build();
        var response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());

        try (var stream = response.body()) {
            // HttpRequest's timeout ends once the headers arrive; this one covers the whole body.
            var expired = new AtomicBoolean();
            var watchdog = VaultHttp.watchDeadline(deadline, stream, expired);
            try {
                return readResponse(response.statusCode(), stream);
            } catch (IOException | UncheckedIOException e) {
                if (expired.get())
                    throw new HttpTimeoutException("Vault's answer took longer than " + timeout + ".");
                throw e;
            } finally {
                watchdog.interrupt();
            }
        }
    }

    // Reads Vault's whole answer into an array of this class's own: returned for a success, for the
    // caller to zero, and otherwise zeroed here once its errors are read.
    private Answer readResponse(int status, InputStream stream) throws IOException {
        // One byte over the limit, so a body that doesn't fit is noticed rather than truncated.
        var buffer = new byte[MAX_RESPONSE_LENGTH + 1];
        var returned = false;
        try {
            var length = 0;
            for (int read; length < buffer.length && (read = stream.read(buffer, length, buffer.length - length)) != -1; )
                length += read;
            if (length > MAX_RESPONSE_LENGTH)
                throw new CryptographicException("Vault's answer for key '" + keyName + "' is over " + MAX_RESPONSE_LENGTH
                        + " bytes; a transit answer is far smaller.");

            if (status >= 200 && status < 300) {
                returned = true;
                return new Answer(buffer, length);
            }

            var errors = readErrors(buffer, length);
            var detail = errors != null && !errors.isEmpty() ? ": " + String.join("; ", errors) : "";
            throw new VaultRequestException("Vault answered " + status + reasonPhrase(status) + detail, status);
        } finally {
            if (!returned)
                ArrayUtility.zeroMemory(buffer);
        }
    }

    // Takes data.plaintext (decoded) or data.ciphertext out of a successful answer into result, then
    // zeroes the answer and the copy of the value read out of it.
    private int readAnswer(Answer answer, String operation, byte[] result, boolean plaintext) {
        // Never longer than the answer it is read out of.
        var value = new byte[answer.length()];
        try {
            var length = readData(answer.bytes(), answer.length(), plaintext ? "plaintext" : "ciphertext", operation, value);
            return plaintext ? decodePlaintext(value, length, result) : copyCiphertext(value, length, result, operation);
        } finally {
            ArrayUtility.zeroMemory(value);
            ArrayUtility.zeroMemory(answer.bytes());
        }
    }

    // Copies the string at data.{name} in a successful answer into value, unescaped, and returns its
    // length. Refused if it is missing or repeated, isn't a string, or the answer's warnings say
    // Vault ignored a parameter - as a Vault too old for associated_data does, leaving a DEK bound to
    // no context.
    private int readData(byte[] json, int jsonLength, String name, String operation, byte[] value) {
        var length = 0;
        var found = false;
        var ignoredParameter = false;
        try {
            var reader = new JsonReader(json, jsonLength);
            if (!reader.read() || reader.token() != Token.START_OBJECT)
                throw malformed(operation);

            while (reader.read() && reader.token() == Token.PROPERTY_NAME) {
                if (reader.valueTextEquals("data")) {
                    reader.read();
                    if (reader.token() != Token.START_OBJECT) {
                        reader.skip();
                        continue;
                    }

                    while (reader.read() && reader.token() == Token.PROPERTY_NAME) {
                        var isValue = reader.valueTextEquals(name);
                        reader.read();
                        if (!isValue) {
                            reader.skip();
                            continue;
                        }

                        if (found || reader.token() != Token.STRING)
                            throw malformed(operation);
                        // Vault doesn't escape base64 or its ciphertext, but a proxy re-encoding the
                        // answer might.
                        length = reader.copyString(value);
                        found = true;
                    }
                } else if (reader.valueTextEquals("warnings")) {
                    reader.read();
                    if (reader.token() != Token.START_ARRAY) {
                        reader.skip();
                        continue;
                    }

                    while (reader.read() && reader.token() != Token.END_ARRAY) {
                        // A warning holds no key material, so may become a String.
                        if (reader.token() == Token.STRING && reader.getString().toLowerCase(Locale.ROOT).contains("unrecognized parameters"))
                            ignoredParameter = true;
                        reader.skip();
                    }
                } else {
                    reader.read();
                    reader.skip();
                }
            }

            // Anything after the root object makes the answer not Vault's.
            if (reader.read())
                throw malformed(operation);
        } catch (JsonReader.Malformed e) {
            throw malformed(operation);
        }

        if (ignoredParameter)
            throw new CryptographicException("Vault transit " + operation + " for key '" + keyName + "' ignored a parameter it was sent, "
                    + "so its answer can't be used: a context needs a Vault that supports associated_data.");
        if (!found || length == 0)
            throw new CryptographicException("Vault transit " + operation + " for key '" + keyName + "' returned no " + name + ".");
        return length;
    }

    private CryptographicException malformed(String operation) {
        return new CryptographicException("Vault transit " + operation + " for key '" + keyName + "' returned a response that isn't Vault's.");
    }

    private int copyCiphertext(byte[] ciphertext, int length, byte[] result, String operation) {
        if (!isVaultCiphertext(ciphertext, length))
            throw new CryptographicException("Vault transit " + operation + " for key '" + keyName + "' returned something that isn't a ciphertext.");

        // A key file over the limit would be refused when read back, so refuse to produce one.
        if (length > WrappedKeyLimits.MAX_BYTES)
            throw new CryptographicException("Vault transit " + operation + " for key '" + keyName + "' returned " + length
                    + " bytes; a wrapped DEK is at most " + WrappedKeyLimits.MAX_BYTES + ".");
        if (length > result.length)
            throw new IllegalArgumentException("The wrapped DEK is " + length + " bytes; result holds " + result.length + ".");

        System.arraycopy(ciphertext, 0, result, 0, length);
        return length;
    }

    // Decodes the revealed key into result, through an array that is zeroed: decoded straight into
    // result, a key too long for it would be partly written before that was known.
    private int decodePlaintext(byte[] base64, int length, byte[] result) {
        var decoded = new byte[length / 4 * 3];
        try {
            var decodedLength = decodeBase64(base64, length, decoded);
            if (decodedLength <= 0)
                throw new CryptographicException("Vault transit unwrap for key '" + keyName + "' returned a plaintext that isn't base64.");
            if (decodedLength > result.length)
                throw new IllegalArgumentException("The revealed key is " + decodedLength + " bytes; result holds " + result.length + ".");

            System.arraycopy(decoded, 0, result, 0, decodedLength);
            return decodedLength;
        } finally {
            ArrayUtility.zeroMemory(decoded);
        }
    }

    // Turns a failure that outlasted the retries, or one not worth retrying, into the
    // CryptographicException every KeyWrapper fails with, the failure as its cause.
    private CryptographicException failed(String operation, Exception failure) {
        String reason;
        if (failure instanceof HttpTimeoutException)
            reason = "no answer within " + timeout;
        else if (failure.getMessage() != null)
            reason = failure.getMessage();
        else
            reason = failure.getClass().getSimpleName();
        return new CryptographicException("Vault transit " + operation + " failed for key '" + keyName + "': " + reason, failure);
    }

    // The errors Vault listed in an error answer: a string as its text, anything else as its JSON
    // text; empty if the answer is a JSON object without errors; null if it isn't Vault's JSON. An
    // error answer holds no key material.
    private static List<String> readErrors(byte[] body, int length) {
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

    // " Bad Request" and the like, for the statuses Vault and the proxies in front of it answer
    // with; "" for any other.
    private static String reasonPhrase(int status) {
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

    // The length of base64 for length bytes, padded.
    private static int base64Length(int length) {
        return (length + 2) / 3 * 4;
    }

    // Writes src[0, length) as padded base64 into dst from offset; returns the index just past it.
    private static int encodeBase64(byte[] src, int length, byte[] dst, int offset) {
        var o = offset;
        var i = 0;
        for (; i + 3 <= length; i += 3) {
            var bits = (src[i] & 0xFF) << 16 | (src[i + 1] & 0xFF) << 8 | (src[i + 2] & 0xFF);
            dst[o++] = BASE64_ALPHABET[bits >>> 18];
            dst[o++] = BASE64_ALPHABET[(bits >>> 12) & 0x3F];
            dst[o++] = BASE64_ALPHABET[(bits >>> 6) & 0x3F];
            dst[o++] = BASE64_ALPHABET[bits & 0x3F];
        }
        if (i < length) {
            var bits = (src[i] & 0xFF) << 16 | (i + 1 < length ? (src[i + 1] & 0xFF) << 8 : 0);
            dst[o++] = BASE64_ALPHABET[bits >>> 18];
            dst[o++] = BASE64_ALPHABET[(bits >>> 12) & 0x3F];
            dst[o++] = i + 1 < length ? BASE64_ALPHABET[(bits >>> 6) & 0x3F] : (byte) '=';
            dst[o++] = '=';
        }
        return o;
    }

    // Decodes padded base64 src[0, length) into dst, which holds length / 4 * 3 bytes; returns the
    // number of bytes written, or -1 if it isn't padded base64 (as .NET's Base64.DecodeFromUtf8
    // requires, so "AAA" is refused, not read as two bytes).
    private static int decodeBase64(byte[] src, int length, byte[] dst) {
        if (length == 0 || length % 4 != 0)
            return -1;

        var written = 0;
        for (var i = 0; i < length; i += 4) {
            var last = i + 4 == length;
            var a = base64Value(src[i]);
            var b = base64Value(src[i + 1]);
            if (a < 0 || b < 0)
                return -1;

            if (last && src[i + 3] == '=') {
                dst[written++] = (byte) (a << 2 | b >> 4);
                if (src[i + 2] == '=')
                    break;
                var c = base64Value(src[i + 2]);
                if (c < 0)
                    return -1;
                dst[written++] = (byte) ((b & 0xF) << 4 | c >> 2);
                break;
            }

            var c = base64Value(src[i + 2]);
            var d = base64Value(src[i + 3]);
            if (c < 0 || d < 0)
                return -1;
            dst[written++] = (byte) (a << 2 | b >> 4);
            dst[written++] = (byte) ((b & 0xF) << 4 | c >> 2);
            dst[written++] = (byte) ((c & 0x3) << 6 | d);
        }
        return written;
    }

    // A base64 character's value, 0-63; -1 for anything else, '=' included.
    private static int base64Value(byte c) {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';
        if (c >= 'a' && c <= 'z')
            return c - 'a' + 26;
        if (c >= '0' && c <= '9')
            return c - '0' + 52;
        if (c == '+')
            return 62;
        if (c == '/')
            return 63;
        return -1;
    }

    // Strict UTF-8, as .NET and the other ports encode the context: an unpaired surrogate would
    // otherwise be replaced, binding a context that differs from the one the caller gave.
    private static byte[] encodeContext(String context) {
        if (context == null)
            return new byte[0];
        try {
            return Utf8Utility.encodeStrict(context);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The context isn't well-formed text: it holds an unpaired surrogate.", e);
        }
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    private static CancellationException cancelled() {
        return new CancellationException("The Vault transit call was abandoned: the thread making it was interrupted.");
    }


    /**
     * A successful answer: bytes[0, length) of an array the reader zeroes. A class, not a record: a
     * record's equals and hashCode would compare the array by identity, not by content.
     */
    private static final class Answer {
        private final byte[] bytes;
        private final int length;

        Answer(byte[] bytes, int length) {
            this.bytes = bytes;
            this.length = length;
        }

        byte[] bytes() {
            return bytes;
        }

        int length() {
            return length;
        }
    }

    /**
     * Publishes a body straight from the array it wraps. BodyPublishers.ofByteArray copies the array
     * into buffers of java.net.http's own on every send, which nothing zeroes; this hands over the
     * array itself, wrapped, so zeroing it reaches the bytes every attempt sent.
     */
    private static final class ArrayBodyPublisher implements HttpRequest.BodyPublisher {
        private final byte[] body;

        ArrayBodyPublisher(byte[] body) {
            this.body = body;
        }

        @Override
        public long contentLength() {
            return body.length;
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
                    subscriber.onNext(ByteBuffer.wrap(body));
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
