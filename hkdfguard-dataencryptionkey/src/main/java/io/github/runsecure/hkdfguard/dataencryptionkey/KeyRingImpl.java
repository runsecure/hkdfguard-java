package io.github.runsecure.hkdfguard.dataencryptionkey;

import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.ProtectedCacheBase;
import io.github.runsecure.hkdfguard.abstractions.VersionedKey;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import org.slf4j.Logger;

/**
 * Tracks {@link DataEncryptionKey}s by version for highly concurrent workloads. get is served
 * straight off a ConcurrentHashMap, so the hot read path never blocks - and records telemetry only
 * on a miss. add is serialized - key registration only happens at startup and rotation, never per
 * operation.
 * <p>
 * The ring tracks its own current version: whichever registered version is highest becomes
 * current, the moment it's added - there is no separate call to designate one, so it can never fall
 * out of sync with what's registered.
 * <p>
 * The ring owns every key added to it: close closes each one that is {@link AutoCloseable} (e.g.
 * {@link DataEncryptionKeyImpl}, which in turn stops its provider's background refresh and zeroes
 * its key).
 * <p>
 * A ring built with ephemeral keys also rotates its encryption key on a schedule (see
 * {@link KeyRingBuilder#withEphemeralKeyRotation}): every interval it generates a fresh ephemeral
 * key and adds it at the current version + 1, so it becomes current and every later encrypt uses
 * it. A superseded ephemeral key stays registered for {@link #getEphemeralKeyRetention()}, so
 * values encrypted under it still decrypt for that long; then the next rotation closes it (zeroing
 * its DEK and stopping its background refresh) and removes it, so a ring never accumulates keys
 * without bound. Keys read from key files are never retired. close stops the rotation before
 * closing any key.
 */
public final class KeyRingImpl implements KeyRing, AutoCloseable {
    // A long, so the "no key yet" sentinel lies outside the int range: every int, including
    // Integer.MIN_VALUE, is a usable version.
    private static final long NO_CURRENT_VERSION = Long.MIN_VALUE;
    private static final AttributeKey<Long> KEY_VERSION = AttributeKey.longKey(AttributeNames.KEY_VERSION);
    private static final AttributeKey<Boolean> BECAME_CURRENT = AttributeKey.booleanKey(AttributeNames.KEY_RING_BECAME_CURRENT);

    private final EncryptedFormatProvider formatProvider;
    private final ConcurrentHashMap<Integer, DataEncryptionKey> keysByVersion = new ConcurrentHashMap<>();
    private final ReentrantLock addGate = new ReentrantLock();
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile long currentVersion = NO_CURRENT_VERSION;

    // Rotation and retention state. Only the single rotation loop (or a test driving one rotation
    // at a time) touches these after construction.
    private Thread rotationThread;
    private volatile boolean rotationStopping;
    private Duration ephemeralKeyRotationInterval;
    private Duration ephemeralKeyRetention;
    private final Set<Integer> ephemeralVersions = new HashSet<>();
    // Version -> the System.nanoTime() at which a rotation first saw it superseded. Monotonic, so a
    // wall-clock jump can neither retire a key early nor keep it forever.
    private final Map<Integer, Long> supersededAt = new HashMap<>();

    /** @param formatProvider formats and parses every value this ring's protectors produce */
    public KeyRingImpl(EncryptedFormatProvider formatProvider) {
        this.formatProvider = Objects.requireNonNull(formatProvider, "formatProvider");
    }

    /**
     * How often this ring adds a fresh ephemeral key as its new current version; null when it
     * doesn't rotate (no ephemeral keys, or rotation turned off).
     */
    public Duration getEphemeralKeyRotationInterval() {
        return ephemeralKeyRotationInterval;
    }

    /**
     * How long a superseded ephemeral key stays registered before a rotation retires it; null when
     * this ring doesn't rotate, since only a rotation supersedes a key.
     */
    public Duration getEphemeralKeyRetention() {
        return ephemeralKeyRetention;
    }

    /**
     * Enables retirement: {@code versions} are eligible for it (every version a later rotation adds
     * is too), and {@code retention} is how long a superseded one is kept. Called once, by
     * KeyRingBuilder, before rotation starts.
     */
    void configureEphemeralKeyRetention(Duration retention, Collection<Integer> versions) {
        ephemeralKeyRetention = retention;
        ephemeralVersions.addAll(versions);
    }

    /**
     * Starts the scheduled rotation: every {@code interval}, create a key with {@code createKey} and
     * add it at the current version + 1. Called once, by KeyRingBuilder.
     */
    void startEphemeralKeyRotation(Duration interval, Supplier<CompletableFuture<DataEncryptionKey>> createKey, Logger logger) {
        ephemeralKeyRotationInterval = interval;
        // A platform thread: rotation calls the key wrapper, which may block in native code or under
        // a monitor - either pins a virtual thread's carrier on Java 21.
        rotationThread = Thread.ofPlatform().daemon().name("hkdfguard-key-ring-rotation").start(() -> runRotationLoop(interval, createKey, logger));
    }

    private void runRotationLoop(Duration interval, Supplier<CompletableFuture<DataEncryptionKey>> createKey, Logger logger) {
        try {
            var next = System.nanoTime() + interval.toNanos();
            while (!rotationStopping) {
                try {
                    var wait = next - System.nanoTime();
                    if (wait > 0)
                        Thread.sleep(Duration.ofNanos(wait));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                if (rotationStopping)
                    return;

                next += interval.toNanos();
                if (next < System.nanoTime())
                    next = System.nanoTime();

                try {
                    rotateEphemeralKey(createKey, logger, () -> rotationStopping);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Throwable t) {
                    // A failure on the way out of a shutdown (rotate rethrows those): nothing to report.
                    if (rotationStopping)
                        return;

                    // rotate records and logs its own failures; this one escaped it (telemetry
                    // failing, say). Report it the same way and try again next interval.
                    quietly(() -> HkdfGuardLog.ephemeralKeyRotationFailed(logger, (int) currentVersion, t));
                }
            }
        } catch (Throwable t) {
            // Every failure of a single rotation is contained above, so reaching here is a bug or
            // a failure of the loop itself - never end the thread silently.
            if (!rotationStopping)
                quietly(() -> HkdfGuardLog.backgroundTaskTerminated(logger, "ephemeral key rotation",
                        "The current ephemeral key stays in use and superseded keys are no longer retired.", t));
        }
    }

    // Runs logging that must not stop the rotation loop.
    private static void quietly(Runnable action) {
        try {
            action.run();
        } catch (Throwable ignored) {
            // Diagnostics are best effort.
        }
    }

    /**
     * One rotation: create a fresh key and add it at the current version + 1, then retire every
     * ephemeral key whose retention has run out. A failure - the key wrapper unavailable, the next
     * version already taken, versions exhausted - is recorded and logged, the current key stays in
     * use, and the next interval tries again. During shutdown ({@code stopping} true) a failure is
     * rethrown instead, and a key created but not added is always closed.
     *
     * @return true if a new key became current
     * @throws InterruptedException shutdown interrupted the wait for a new key
     */
    boolean rotateEphemeralKey(Supplier<CompletableFuture<DataEncryptionKey>> createKey, Logger logger, BooleanSupplier stopping)
            throws InterruptedException {
        try (var op = HkdfGuardTelemetry.DATA_PROTECTION.startSpan(SpanNames.DataProtection.KEY_RING_ROTATE_EPHEMERAL)) {
            var current = getCurrentVersion();
            if (current == Integer.MAX_VALUE) {
                var exhausted = new IllegalStateException(
                        "Version " + Integer.MAX_VALUE + " is current, so there is no higher version to rotate to; the current key stays in use.");
                op.recordException(exhausted);
                HkdfGuardLog.ephemeralKeyRotationFailed(logger, current, exhausted);
                return false;
            }

            DataEncryptionKey key = null;
            try {
                var pending = createKey.get();
                try {
                    key = pending.get();
                } catch (InterruptedException e) {
                    // Shutdown: a key the wrapper still produces is never added, so close it.
                    pending.thenAccept(KeyRingImpl::closeQuietly);
                    throw e;
                }

                add(current + 1, key);
                ephemeralVersions.add(current + 1);
                op.span().setAttribute(KEY_VERSION, (long) current + 1);
                HkdfGuardLog.ephemeralKeyRotated(logger, current + 1);
            } catch (ExecutionException | RuntimeException | Error e) {
                // Not added, so not owned by the ring: release its revealed key here, on every path.
                // Errors too: a key factory failing with, say, a LinkageError is one more failed
                // rotation, not a reason to stop rotating.
                closeQuietly(key);

                var cause = e instanceof ExecutionException ? e.getCause() : e;
                if (stopping.getAsBoolean())
                    throw cause instanceof RuntimeException runtime ? runtime : new IllegalStateException(cause);

                op.recordException(cause);
                HkdfGuardLog.ephemeralKeyRotationFailed(logger, current, cause);
                return false;
            }

            retireSupersededEphemeralKeys(System.nanoTime(), logger, stopping);
            return true;
        }
    }

    /**
     * Retires every ephemeral key that stopped being current at least the retention ago: removes it
     * from the ring, so get/find no longer find it, and closes it, zeroing its DEK and stopping its
     * background refresh. An ephemeral key is first seen as superseded by the rotation that follows
     * the one replacing it, so it is kept for at least the retention - never less. Does nothing on a
     * ring without retention configured. Key-file versions are never touched.
     *
     * @param now the current System.nanoTime(); a parameter so tests can move time
     */
    void retireSupersededEphemeralKeys(long now, Logger logger, BooleanSupplier stopping) {
        var retention = ephemeralKeyRetention;
        if (retention == null)
            return;

        var current = getCurrentVersion();
        for (var version : ephemeralVersions)
            if (version != current)
                supersededAt.putIfAbsent(version, now);

        for (var entry : new ArrayList<>(supersededAt.entrySet())) {
            var version = entry.getKey();
            if (version == current || now - entry.getValue() < retention.toNanos())
                continue;

            supersededAt.remove(version);
            ephemeralVersions.remove(version);
            var key = keysByVersion.remove(version);
            if (key == null)
                continue;

            try {
                if (key instanceof AutoCloseable closeable)
                    closeable.close();
                HkdfGuardLog.ephemeralKeyRetired(logger, version);
            } catch (Exception e) {
                // Already out of the ring; a failure to release it must not stop the rotation loop.
                if (!stopping.getAsBoolean())
                    HkdfGuardLog.ephemeralKeyRetirementFailed(logger, version, e);
            }
        }
    }

    // Stops the rotation loop and waits for a rotation in flight, before any key is closed - so a
    // key can't be added to a ring that is being torn down.
    // An uninterruptible wait: an interrupt is remembered and restored once the join returns.
    // Restoring it inside the catch, as S2142 asks, would make the next join throw at once and spin.
    @SuppressWarnings("java:S2142")
    private void stopEphemeralKeyRotation() {
        var thread = rotationThread;
        if (thread == null)
            return;

        rotationStopping = true;
        thread.interrupt();
        if (Thread.currentThread() == thread)
            return;

        var interrupted = false;
        while (true) {
            try {
                thread.join();
                break;
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted)
            Thread.currentThread().interrupt();
    }

    /**
     * The highest version registered so far - what encrypt-side operations protect new data with.
     *
     * @throws IllegalStateException no key has been added yet
     */
    @Override
    public int getCurrentVersion() {
        var current = currentVersion;
        if (current == NO_CURRENT_VERSION)
            throw new IllegalStateException("No current version has been set. Add a key first.");
        return (int) current;
    }

    /**
     * Registers a key for the given version. If version is higher than every version registered so
     * far, it becomes the new current version. On success the ring takes ownership of {@code key};
     * if add throws, ownership stays with the caller.
     *
     * @throws IllegalArgumentException a key for this version is already registered
     * @throws IllegalStateException    the ring has been closed
     */
    public void add(int version, DataEncryptionKey key) {
        Objects.requireNonNull(key, "key");
        var telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        try (var op = telemetry.startSpan(SpanNames.DataProtection.KEY_RING_ADD)) {
            addGate.lock();
            try {
                if (closed.get())
                    throw new IllegalStateException("This key ring has been closed.");

                if (keysByVersion.putIfAbsent(version, key) != null)
                    throw new IllegalArgumentException("A key for version " + version + " is already registered.");

                var current = currentVersion;
                var becameCurrent = current == NO_CURRENT_VERSION || version > current;
                if (becameCurrent)
                    currentVersion = version;

                if (telemetry.isSensitiveLoggingEnabled())
                    telemetry.logSensitiveOperation(op.span(), SpanNames.DataProtection.KEY_RING_ADD,
                            Attributes.of(KEY_VERSION, (long) version, BECAME_CURRENT, becameCurrent));
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            } finally {
                addGate.unlock();
            }
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws NoSuchElementException no key is registered for this version: it was never added, or
     *                                it was a superseded ephemeral key whose retention ran out
     */
    @Override
    public DataEncryptionKey get(int version) {
        var key = keysByVersion.get(version);
        if (key != null)
            return key;

        var notFound = new NoSuchElementException("No key is registered for version " + version + ".");
        try (var op = HkdfGuardTelemetry.DATA_PROTECTION.startSpan(SpanNames.DataProtection.KEY_RING_GET)) {
            op.recordException(notFound);
        }
        throw notFound;
    }

    /**
     * The key registered for {@code version}, without throwing - for the high-frequency hot path,
     * where exception overhead (and telemetry) on a routine miss is unacceptable.
     */
    @Override
    public Optional<DataEncryptionKey> find(int version) {
        return Optional.ofNullable(keysByVersion.get(version));
    }

    /**
     * The current version together with its key - what encrypt-side operations resolve fresh on
     * every call, so they always reflect the latest rotation.
     *
     * @throws IllegalStateException no key has been added yet
     */
    @Override
    public VersionedKey getCurrent() {
        try {
            var version = getCurrentVersion();
            return new VersionedKey(version, get(version));
        } catch (IllegalStateException e) {
            try (var op = HkdfGuardTelemetry.DATA_PROTECTION.startSpan(SpanNames.DataProtection.KEY_RING_GET_CURRENT)) {
                op.recordException(e);
            }
            throw e;
        }
    }

    /**
     * Creates a {@link DataProtector} bound to this ring - the only way to obtain one. Encrypt
     * resolves the current version on every call, and formats/parses via this ring's
     * {@link EncryptedFormatProvider}.
     *
     * @param name used as the protector's Additional Authenticated Data on every encrypt/decrypt.
     *             {@code ProtectedConfigurationPurpose.forKey(key)} names the protector a
     *             configuration reader uses for that key, which is how pipeline-protected values
     *             decrypt; that sharing is intended.
     * @throws NullPointerException     name is null
     * @throws IllegalArgumentException name is empty - an empty purpose binds nothing - or starts with
     *                                  {@link ProtectedCacheBase#AAD_PREFIX}, whose AADs belong to
     *                                  protected caches alone, or isn't valid UTF-16
     */
    public DataProtector createProtector(String name) {
        Objects.requireNonNull(name, "name");
        if (name.isEmpty())
            throw new IllegalArgumentException("A protector name must not be empty.");
        if (name.startsWith(ProtectedCacheBase.AAD_PREFIX))
            throw new IllegalArgumentException("Protector names starting with '" + ProtectedCacheBase.AAD_PREFIX
                    + "' are reserved for ProtectedCache's entries.");

        return new DataProtectorImpl(name, this, formatProvider);
    }

    /**
     * Closes the ring without blocking the caller: stops rotation, then closes every registered key
     * on a background thread. Safe to call more than once.
     */
    public CompletableFuture<Void> closeAsync() {
        if (closed.get())
            return CompletableFuture.completedFuture(null);

        var done = new CompletableFuture<Void>();
        Thread.ofPlatform().daemon().name("hkdfguard-key-ring-close").start(() -> {
            try {
                close();
                done.complete(null);
            } catch (Throwable t) {
                done.completeExceptionally(t);
            }
        });
        return done;
    }

    /**
     * Stops rotation, then closes every registered key that is {@link AutoCloseable}. Safe to call
     * more than once; keys stay registered, so a later operation fails with the key's own error.
     */
    @Override
    public void close() {
        if (closed.getAndSet(true))
            return;

        stopEphemeralKeyRotation();
        addGate.lock();
        try {
            for (var key : keysByVersion.values())
                closeQuietly(key);
        } finally {
            addGate.unlock();
        }
    }

    private static void closeQuietly(DataEncryptionKey key) {
        if (key instanceof AutoCloseable closeable) {
            try {
                closeable.close();
            } catch (Exception ignored) {
                // Releasing a key must not stop the others from being released.
            }
        }
    }
}
