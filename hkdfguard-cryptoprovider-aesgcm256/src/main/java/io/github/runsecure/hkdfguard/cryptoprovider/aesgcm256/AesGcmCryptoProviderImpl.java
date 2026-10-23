package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptoProvider;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.RefreshFailurePolicy;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.EventNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.github.runsecure.hkdfguard.diagnostics.SpanScope;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks one cached {@link AesGcmCryptoSession}, bound to a single wrapped DEK. A background virtual
 * thread, ticking every expirySeconds, proactively reveals the DEK fresh (via
 * {@code keyWrapper.unwrapAsync(wrapped, ...)}) and builds the next session before the current one
 * expires, then swaps it in - so encrypt/decrypt never pay the unwrap cost themselves; only
 * {@link #createAsync} does, once. The replaced session is kept for one more interval before being
 * closed (zeroing its key), so an operation that captured it just before the swap completes
 * normally. Thread-safe: only createAsync and the single background loop ever reveal the key.
 * <p>
 * A refresh re-reveals the <em>same</em> DEK, so it is a periodic re-check that the KEK is still
 * accessible, not a bound on how long the DEK value exists in memory. What happens when that check
 * fails is the refresh-failure policy: by default,
 * {@link RefreshFailurePolicy#DEFAULT_MAX_REFRESH_FAILURES} consecutive failures close every session
 * (zeroing the DEK) and suspend encrypt/decrypt - they throw {@link CryptographicException} - until
 * a later refresh succeeds and operation resumes. Passing a null {@code maxRefreshFailures} instead
 * keeps the last good session in use indefinitely (fail open).
 */
public final class AesGcmCryptoProviderImpl implements CryptoProvider {
    /**
     * Encryptions after which this provider refuses to encrypt (decryption keeps working): half of
     * NIST SP 800-38D's 2^32 random-nonce limit, since a per-process counter can't see the other
     * processes sharing the same key file. The count is per DEK and shared by every provider in
     * this process that reveals it; a background refresh re-reveals the same key, so it does not
     * reset the count.
     */
    public static final long MAX_ENCRYPTIONS_PER_KEY = EncryptionBudget.DEFAULT_LIMIT;

    /**
     * Encryptions after which an {@link EventNames#ENCRYPTION_BUDGET_WARNING} event is raised, once,
     * on the encrypt span that crosses it.
     */
    public static final long ENCRYPTION_WARNING_THRESHOLD = EncryptionBudget.DEFAULT_WARNING_THRESHOLD;

    private static final int KEY_LENGTH = 32;
    private static final int EXTRA_ALLOCATION_LENGTH = AesGcmCryptoSession.NONCE_SIZE + AesGcmCryptoSession.TAG_SIZE;
    private static final byte[] EMPTY = new byte[0];
    private static final AttributeKey<Long> CONSECUTIVE_FAILURES = AttributeKey.longKey(AttributeNames.CONSECUTIVE_FAILURES);

    private final KeyWrapper keyWrapper;
    private final EncryptionBudget budget;
    private final Integer maxRefreshFailures;
    private final Logger logger;
    private final byte[] wrapped;
    private final Duration interval;
    private final AtomicInteger consecutiveRefreshFailures = new AtomicInteger();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Object gate = new Object();
    private final Thread refreshThread;
    private volatile boolean closing;
    // Set if the refresh loop ever ends other than by close: nothing re-checks the KEK after that.
    private volatile boolean refreshLoopTerminated;
    private volatile AesGcmCryptoSession current;
    // The session a refresh replaced. encrypt/decrypt read current without a lock, so a call that
    // captured the old session just before a swap may still be using it; it's closed one interval
    // later, on the next swap (or on close), rather than immediately.
    private AesGcmCryptoSession retiring;
    // A reveal a refresh stopped waiting for, while it may still be running. Touched only by the
    // refresh thread. See refresh.
    private CompletableFuture<AesGcmCryptoSession> abandonedReveal;

    // Construction always goes through createAsync, so the first key reveal is never blocked on.
    private AesGcmCryptoProviderImpl(KeyWrapper keyWrapper, byte[] wrapped, int expirySeconds, Integer maxRefreshFailures,
                                     EncryptionBudget budget, AesGcmCryptoSession firstSession, Logger logger) {
        this.keyWrapper = keyWrapper;
        this.wrapped = wrapped;
        this.interval = Duration.ofSeconds(expirySeconds);
        this.maxRefreshFailures = maxRefreshFailures;
        this.budget = budget;
        this.logger = logger;
        this.current = firstSession;

        refreshThread = Thread.ofVirtual().name("hkdfguard-aesgcm-refresh").unstarted(this::runRefreshLoop);
        refreshThread.start();
    }

    /**
     * {@link #createAsync(KeyWrapper, byte[], int, Integer, Logger)}, failing closed after
     * {@link RefreshFailurePolicy#DEFAULT_MAX_REFRESH_FAILURES} failures and logging through this
     * class's SLF4J logger.
     */
    public static CompletableFuture<AesGcmCryptoProviderImpl> createAsync(KeyWrapper keyWrapper, byte[] wrapped, int expirySeconds) {
        return createAsync(keyWrapper, wrapped, expirySeconds, RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES, null);
    }

    /** {@link #createAsync(KeyWrapper, byte[], int, Integer, Logger)}, logging through this class's SLF4J logger. */
    public static CompletableFuture<AesGcmCryptoProviderImpl> createAsync(KeyWrapper keyWrapper, byte[] wrapped, int expirySeconds,
                                                                          Integer maxRefreshFailures) {
        return createAsync(keyWrapper, wrapped, expirySeconds, maxRefreshFailures, null);
    }

    /**
     * Creates a provider: reveals the DEK through {@code keyWrapper} (asynchronously, so a
     * network-backed key wrapper never blocks the caller) and starts the background refresh.
     *
     * @param keyWrapper         reveals wrapped's DEK - see {@link KeyWrapper#unwrapAsync}
     * @param wrapped            the wrapped DEK payload this provider's sessions decrypt; owned by
     *                           the provider from here on, and zeroed when it's closed
     * @param expirySeconds      how long each session is used before the next background refresh,
     *                           1-300 seconds; also the refresh interval
     * @param maxRefreshFailures consecutive failed background refreshes tolerated before failing
     *                           closed (see the class description), at least 1; null to fail open
     * @param logger             receives an error for every failed background refresh, an error
     *                           marked CRITICAL when key access is suspended, an info entry when it
     *                           resumes, and a warning when the key nears its encryption limit;
     *                           null for this class's SLF4J logger
     * @return completes with the provider once the first key is revealed, or exceptionally if that fails
     * @throws IllegalArgumentException expirySeconds is not between 1 and 300, or maxRefreshFailures is below 1
     */
    public static CompletableFuture<AesGcmCryptoProviderImpl> createAsync(KeyWrapper keyWrapper, byte[] wrapped, int expirySeconds,
                                                                          Integer maxRefreshFailures, Logger logger) {
        return createAsync(keyWrapper, wrapped, expirySeconds, maxRefreshFailures, null, logger);
    }

    /** Tests: a budget of their own, failing open. */
    static CompletableFuture<AesGcmCryptoProviderImpl> createAsync(KeyWrapper keyWrapper, byte[] wrapped, int expirySeconds, EncryptionBudget budget) {
        return createAsync(keyWrapper, wrapped, expirySeconds, null, budget, null);
    }

    /**
     * @param budget the count to draw on; null for the process-wide one for whichever key is
     *               revealed (see {@link EncryptionBudget#forKey}). Tests pass their own.
     */
    static CompletableFuture<AesGcmCryptoProviderImpl> createAsync(KeyWrapper keyWrapper, byte[] wrapped, int expirySeconds,
                                                                   Integer maxRefreshFailures, EncryptionBudget budget, Logger logger) {
        Objects.requireNonNull(keyWrapper, "keyWrapper");
        Objects.requireNonNull(wrapped, "wrapped");
        validate(expirySeconds, maxRefreshFailures);
        var effectiveLogger = logger != null ? logger : LoggerFactory.getLogger(AesGcmCryptoProviderImpl.class);

        return revealAsync(keyWrapper, wrapped, budget, effectiveLogger)
                .thenApply(first -> new AesGcmCryptoProviderImpl(keyWrapper, wrapped, expirySeconds, maxRefreshFailures,
                        first.budget(), first, effectiveLogger));
    }

    /**
     * Checks the arguments of createAsync, before any key-wrapper call is made.
     *
     * @throws IllegalArgumentException either is out of range
     */
    static void validate(int expirySeconds, Integer maxRefreshFailures) {
        if (expirySeconds < 1 || expirySeconds > 300)
            throw new IllegalArgumentException("expirySeconds must be between 1 and 300; it is " + expirySeconds + ".");
        if (maxRefreshFailures != null && maxRefreshFailures < 1)
            throw new IllegalArgumentException("maxRefreshFailures must be at least 1; it is " + maxRefreshFailures + ".");
    }

    /** The configured refresh-failure policy; null means fail open. */
    public Integer getMaxRefreshFailures() {
        return maxRefreshFailures;
    }

    /**
     * True while this provider has failed closed: its sessions are closed and every
     * encrypt/decrypt throws, until a background refresh succeeds.
     */
    public boolean isKeyAccessSuspended() {
        return current == null && !closed.get();
    }

    /** Encryptions performed under this provider's key so far - see {@link #MAX_ENCRYPTIONS_PER_KEY}. */
    public long getEncryptionCount() {
        return budget.getCount();
    }

    /** The session in use, for tests; null while suspended or after close. */
    AesGcmCryptoSession currentSession() {
        return current;
    }

    @Override
    public int encrypt(byte[] plaintext, byte[] result) {
        return encrypt(plaintext, EMPTY, result);
    }

    @Override
    public int encrypt(byte[] plaintext, byte[] aad, byte[] result) {
        Objects.requireNonNull(plaintext, "plaintext");
        while (true) {
            AesGcmCryptoSession session;
            try {
                session = session();
            } catch (RuntimeException e) {
                // Suspended or closed: no session will run its own zeroing, so honour the
                // CryptoProvider contract here.
                ArrayUtility.zeroMemory(plaintext);
                throw e;
            }

            // Once it starts, the session zeroes plaintext itself, on success and on every failure.
            // -1 means it was retired and closed after it was read here, before it started -
            // nothing was touched, so go round again for the session that replaced it. current is
            // never set to a closed session, so this ends.
            var written = session.tryEncrypt(plaintext, aad, result);
            if (written >= 0)
                return written;
        }
    }

    @Override
    public int decrypt(byte[] ciphertext, byte[] result) {
        return decrypt(ciphertext, EMPTY, result);
    }

    @Override
    public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
        // As encrypt: a session retired between reading it and starting is skipped for the current one.
        while (true) {
            var written = session().tryDecrypt(ciphertext, aad, result);
            if (written >= 0)
                return written;
        }
    }

    private AesGcmCryptoSession session() {
        var session = current;
        if (session != null)
            return session;

        if (closed.get())
            throw new IllegalStateException("This AES-GCM crypto provider has been closed.");
        if (refreshLoopTerminated)
            throw new CryptographicException("Key access is suspended: the background key refresh stopped unexpectedly, so the KEK can no longer"
                    + " be re-checked. Create a new provider (restart the process) to resume.");
        throw new CryptographicException("Key access is suspended: " + maxRefreshFailures
                + " consecutive attempts to re-reveal the key through the key wrapper failed. Operations resume once a refresh succeeds.");
    }

    @Override
    public int getEncryptedAllocationLength(int length) {
        return length + EXTRA_ALLOCATION_LENGTH;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Never negative: input shorter than the nonce and tag can't be valid ciphertext, and decrypt
     * rejects it, but a size computed from it must still be a usable buffer length.
     */
    @Override
    public int getDecryptedAllocationLength(int length) {
        return Math.max(0, length - EXTRA_ALLOCATION_LENGTH);
    }

    // Reveals the DEK through the key wrapper and builds a session around it. Shared by the first
    // reveal and every background refresh. A null budget means the process-wide one for whichever
    // key is revealed.
    private static CompletableFuture<AesGcmCryptoSession> revealAsync(KeyWrapper keyWrapper, byte[] wrapped,
                                                                      EncryptionBudget budget, Logger logger) {
        // Becomes the session's key and lives until the next refresh.
        var key = new byte[KEY_LENGTH];
        CompletableFuture<Integer> unwrap;
        try {
            unwrap = Objects.requireNonNull(keyWrapper.unwrapAsync(wrapped, key), "unwrapAsync returned null");
        } catch (RuntimeException e) {
            ArrayUtility.zeroMemory(key);
            return CompletableFuture.failedFuture(e);
        }

        return unwrap.handle((written, error) -> {
            if (error != null) {
                ArrayUtility.zeroMemory(key);
                throw error instanceof CompletionException completion ? completion : new CompletionException(error);
            }

            try {
                // A wrapper that reveals fewer bytes (e.g. a misconfigured KMS returning a 128-bit
                // data key) would otherwise leave the rest of the key zero and silently weaken
                // every session.
                if (written == null || written != KEY_LENGTH)
                    throw new CryptographicException("Key wrapper revealed " + written + " bytes; a " + KEY_LENGTH + "-byte DEK is required.");

                return new AesGcmCryptoSession(key, budget != null ? budget : EncryptionBudget.forKey(key), logger);
            } catch (RuntimeException e) {
                ArrayUtility.zeroMemory(key);
                throw e;
            }
        });
    }

    // Only the single background loop refreshes once the provider exists.
    //
    // Each refresh waits at most one refresh interval for the key wrapper. A wrapper that hangs
    // rather than failing (a busy TPM resource manager, a keychain prompt nobody can answer, a KMS
    // endpoint that never replies) must still count towards the refresh-failure policy, or a revoked
    // KEK would never suspend key access. A reveal that misses its deadline is abandoned, not
    // cancelled - a native call can't be - and until it returns no new one starts, so a stuck key
    // wrapper never accumulates calls; each tick in the meantime is a failed refresh.
    private void refresh() throws InterruptedException, ExecutionException, TimeoutException {
        if (abandonedReveal != null) {
            if (!abandonedReveal.isDone())
                throw new TimeoutException("The key wrapper has still not returned from a refresh that timed out; no new refresh starts until it does.");
            abandonedReveal = null;
        }

        // On a thread of its own: a key wrapper may unwrap synchronously on the calling thread (the
        // native one does), and neither a deadline nor close's interrupt reaches a thread stuck in a
        // native call. A platform thread, since a virtual one would pin its carrier for as long as
        // the call hangs.
        var pending = new CompletableFuture<AesGcmCryptoSession>();
        var revealThread = Thread.ofPlatform().daemon().name("hkdfguard-aesgcm-reveal").start(() -> {
            try {
                revealAsync(keyWrapper, wrapped, budget, logger).whenComplete((session, error) -> {
                    if (error != null)
                        pending.completeExceptionally(error);
                    else
                        pending.complete(session);
                });
            } catch (Throwable t) {
                pending.completeExceptionally(t);
            }
        });

        AesGcmCryptoSession fresh;
        try {
            fresh = pending.get(interval.toNanos(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            abandon(pending, revealThread);
            throw new TimeoutException("The key wrapper did not reveal the key within " + interval.toSeconds() + " seconds.");
        } catch (InterruptedException e) {
            // close interrupted the wait: a session the wrapper still produces is never used.
            abandon(pending, revealThread);
            throw e;
        }

        synchronized (gate) {
            // close may have run while the key was being revealed (from inside the key wrapper,
            // say): never put a session back into a closed provider.
            if (closing) {
                fresh.close();
                return;
            }

            var outgoing = current;
            current = fresh;
            var stale = retiring;
            retiring = outgoing;
            if (stale != null)
                stale.close();
        }
    }

    // Remembers a reveal nobody waits for any more, and zeroes whatever key it eventually reveals.
    // The reveal's thread is interrupted, so a key wrapper that honours interruption (a Java KMS
    // client) gives up promptly; a native call ignores it and is simply left to finish.
    private void abandon(CompletableFuture<AesGcmCryptoSession> pending, Thread revealThread) {
        abandonedReveal = pending;
        pending.thenAccept(AesGcmCryptoSession::close);
        revealThread.interrupt();
    }

    private void runRefreshLoop() {
        try {
            // Ticks at fixed intervals from creation; ticks missed while a slow refresh ran
            // collapse into one, so a refresh never runs back to back with itself more than once.
            var next = System.nanoTime() + interval.toNanos();
            while (!closing) {
                try {
                    var wait = next - System.nanoTime();
                    if (wait > 0)
                        Thread.sleep(Duration.ofNanos(wait));
                } catch (InterruptedException e) {
                    return;
                }

                if (closing)
                    return;

                next += interval.toNanos();
                if (next < System.nanoTime())
                    next = System.nanoTime();

                if (!refreshOnce())
                    return;
            }
        } catch (Throwable t) {
            // refreshOnce contains every failure of a single refresh, so reaching here is a bug or
            // a failure of the loop itself. Without this, the thread would end silently and a
            // fail-closed provider would keep serving its last key forever, unsupervised.
            onRefreshLoopTerminated(t);
        }
    }

    /**
     * The refresh loop has ended for good while the provider is still open. Under fail-closed the
     * key is zeroed and every operation refused from here on, since revocation can no longer be
     * detected; under fail-open the last good key stays in use, as configured. Logged as critical
     * either way. Package-private so tests can drive it: nothing reachable makes the loop die.
     */
    void onRefreshLoopTerminated(Throwable cause) {
        if (closing)
            return;

        refreshLoopTerminated = true;
        String consequence;
        if (maxRefreshFailures != null) {
            // Zero first: the log below runs foreign code that might fail too.
            suspendKeyAccess();
            consequence = "Key access has been suspended and the key zeroed; every operation fails until the process restarts.";
        } else {
            consequence = "The provider fails open, so the last good key stays in use, but a revoked KEK will no longer be detected.";
        }

        var description = consequence;
        quietly(() -> HkdfGuardLog.backgroundTaskTerminated(logger, "background key refresh", description, cause));
    }

    // One background refresh, under its own span. False once the provider is closing. Contains
    // every failure - Errors such as OutOfMemoryError or a LinkageError from the native binding
    // included - so each one counts toward the refresh-failure policy and the loop keeps ticking.
    private boolean refreshOnce() {
        var op = startSpanQuietly(SpanNames.CryptoProviderAesGcm256.BACKGROUND_REFRESH);
        var span = op != null ? op.span() : Span.getInvalid();
        try {
            refresh();
            var previousFailures = consecutiveRefreshFailures.getAndSet(0);
            if (maxRefreshFailures != null && previousFailures >= maxRefreshFailures)
                quietly(() -> HkdfGuardLog.keyAccessResumed(logger, previousFailures));
            return true;
        } catch (InterruptedException e) {
            return false;
        } catch (Throwable t) {
            // Shutdown: swallow whatever an in-flight refresh threw on the way out (e.g. a key
            // wrapper failing because its client was torn down).
            if (closing)
                return false;

            var cause = (t instanceof ExecutionException || t instanceof CompletionException) && t.getCause() != null ? t.getCause() : t;
            var failures = consecutiveRefreshFailures.incrementAndGet();
            var suspend = maxRefreshFailures != null && failures == maxRefreshFailures;

            // Enforce the policy before anything that runs foreign code (telemetry, the logger),
            // so a failure there can't leave the key in use past the limit.
            if (suspend)
                suspendKeyAccess();

            quietly(() -> ComponentTelemetry.recordException(span, cause));
            quietly(() -> HkdfGuardLog.keyRefreshFailed(logger, failures, refreshFailurePolicyDescription(), cause));
            if (suspend) {
                quietly(() -> span.addEvent(EventNames.KEY_ACCESS_SUSPENDED, Attributes.of(CONSECUTIVE_FAILURES, (long) failures)));
                quietly(() -> HkdfGuardLog.keyAccessSuspended(logger, failures));
            }
            return true;
        } finally {
            if (op != null)
                quietly(op::close);
        }
    }

    private String refreshFailurePolicyDescription() {
        return maxRefreshFailures != null
                ? "fail closed after " + maxRefreshFailures + " consecutive failures"
                : "fail open (the last good key stays in use)";
    }

    // Fail closed: zero every revealed copy of the DEK and refuse operations until a refresh
    // succeeds. The next successful refresh swaps a fresh session in and resumes service.
    private void suspendKeyAccess() {
        synchronized (gate) {
            // Null unless a refresh has succeeded since the last swap.
            if (retiring != null) {
                retiring.close();
                retiring = null;
            }

            // Null if a failure streak already suspended, or the refresh loop has terminated.
            var outgoing = current;
            current = null;
            if (outgoing != null)
                outgoing.close();
        }
    }

    // Telemetry is optional: a span that can't be started must never stop a refresh.
    private static SpanScope startSpanQuietly(String spanName) {
        try {
            return HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.startSpan(spanName);
        } catch (Throwable t) {
            return null;
        }
    }

    // Runs telemetry or logging that must not interrupt the refresh loop or its policy.
    private static void quietly(Runnable action) {
        try {
            action.run();
        } catch (Throwable ignored) {
            // Diagnostics are best effort; the policy has already been enforced.
        }
    }

    /**
     * Stops the background refresh without blocking the caller, then zeroes the wrapped payload
     * and every revealed key. A refresh still waiting on the key wrapper is abandoned rather than
     * waited for, so a stuck wrapper can't block close; whatever key it later reveals is zeroed
     * when it arrives. Safe to call more than once.
     */
    @Override
    public CompletableFuture<Void> closeAsync() {
        if (!beginClose())
            return CompletableFuture.completedFuture(null);

        var done = new CompletableFuture<Void>();
        Thread.ofVirtual().name("hkdfguard-aesgcm-close").start(() -> {
            try {
                awaitRefreshThread();
                endClose();
                done.complete(null);
            } catch (Throwable t) {
                done.completeExceptionally(t);
            }
        });
        return done;
    }

    /** Synchronous {@link #closeAsync}. Never waits on a refresh still inside the key wrapper. */
    @Override
    public void close() {
        if (!beginClose())
            return;

        awaitRefreshThread();
        endClose();
    }

    private boolean beginClose() {
        if (closed.getAndSet(true))
            return false;

        closing = true;
        refreshThread.interrupt();
        ArrayUtility.zeroMemory(wrapped);
        return true;
    }

    private void awaitRefreshThread() {
        // Closed from inside the loop (a logger callback, say): it exits on its own.
        if (Thread.currentThread() == refreshThread)
            return;

        var interrupted = false;
        while (true) {
            try {
                refreshThread.join();
                break;
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted)
            Thread.currentThread().interrupt();
    }

    private void endClose() {
        synchronized (gate) {
            if (retiring != null) {
                retiring.close();
                retiring = null;
            }

            // Null if this provider had already failed closed.
            var outgoing = current;
            current = null;
            if (outgoing != null)
                outgoing.close();
        }
    }
}
