package io.github.runsecure.hkdfguard.dataencryptionkey;

import io.github.runsecure.hkdfguard.abstractions.CryptoProvider;
import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.EncryptionLimitReachedException;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A {@link DataEncryptionKey} backed by a {@link CryptoProvider}, which owns the actual key
 * material - how it is revealed and refreshed - and performs the AEAD encrypt/decrypt. This class
 * sizes the output buffer via the provider, trims the result to exactly what was written, and
 * records telemetry for every operation. Owns its provider: close closes it (stopping any
 * background refresh and zeroing its key).
 * <p>
 * A key may carry an {@link EncryptionDeadline}: from its refuseAt on, encrypt throws
 * {@link EncryptionLimitReachedException} while decrypt keeps working. KeyRingBuilder gives every
 * key-file key one, from the file's age.
 */
public final class DataEncryptionKeyImpl implements DataEncryptionKey, AutoCloseable {
    private static final byte[] EMPTY = new byte[0];
    private static final AttributeKey<Long> PLAINTEXT_LENGTH = AttributeKey.longKey(AttributeNames.PLAINTEXT_LENGTH);
    private static final AttributeKey<Long> CIPHERTEXT_LENGTH = AttributeKey.longKey(AttributeNames.CIPHERTEXT_LENGTH);
    private static final AttributeKey<Long> AAD_LENGTH = AttributeKey.longKey(AttributeNames.AAD_LENGTH);

    private final CryptoProvider provider;
    private final EncryptionDeadline deadline;
    private final Clock clock;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean warned = new AtomicBoolean();
    private final AtomicBoolean expired = new AtomicBoolean();

    /** @param provider owned by this key from here on; the key encrypts without a time limit */
    public DataEncryptionKeyImpl(CryptoProvider provider) {
        this(provider, null);
    }

    /**
     * @param provider owned by this key from here on
     * @param deadline when this key stops encrypting; null to encrypt without a time limit
     */
    public DataEncryptionKeyImpl(CryptoProvider provider, EncryptionDeadline deadline) {
        this(provider, deadline, Clock.systemUTC());
    }

    /** Tests and KeyRingBuilder: the deadline checked against {@code clock}. */
    DataEncryptionKeyImpl(CryptoProvider provider, EncryptionDeadline deadline, Clock clock) {
        this.provider = Objects.requireNonNull(provider, "provider");
        this.deadline = deadline;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** When this key stops encrypting; null when it encrypts without a time limit. */
    public EncryptionDeadline getDeadline() {
        return deadline;
    }

    /**
     * Checks the deadline against {@code now}, announcing a warning or expiry the first time each is
     * reached; returns whether this key has stopped encrypting. Each callback runs at most once,
     * however many threads check at the same time. A throwing callback is ignored, so a faulty
     * logger never decides whether a value is encrypted. Also called by KeyRingBuilder, so a
     * current key file nearing or past its age is reported at startup.
     */
    boolean checkDeadline(Instant now) {
        var limit = deadline;
        if (limit == null)
            return false;

        if (!now.isBefore(limit.refuseAt())) {
            // Marks the warning as given too: a warning skipped over is never raised after expiry.
            warned.set(true);
            if (expired.compareAndSet(false, true))
                runQuietly(limit.onExpired());
            return true;
        }

        if (!now.isBefore(limit.warnAt()) && warned.compareAndSet(false, true))
            runQuietly(limit.onWarning());
        return false;
    }

    private static void runQuietly(Runnable callback) {
        if (callback == null)
            return;

        try {
            callback.run();
        } catch (RuntimeException ignored) {
            // See checkDeadline: diagnostics never decide whether a value is encrypted.
        }
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        return encrypt(plaintext, EMPTY);
    }

    /**
     * {@inheritDoc}
     *
     * @throws EncryptionLimitReachedException this key has passed its deadline; it must be rotated,
     *                                         and decryption still works
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) {
        var associatedData = aad == null ? EMPTY : aad;
        var telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        try (var op = telemetry.startSpan(SpanNames.DataProtection.KEY_WRAPPED_KEY_ENCRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.DataProtection.KEY_WRAPPED_KEY_ENCRYPT,
                        Attributes.of(PLAINTEXT_LENGTH, (long) plaintext.length, AAD_LENGTH, (long) associatedData.length));

            try {
                if (checkDeadline(clock.instant())) {
                    // The provider never sees it, so honor the zeroing contract here.
                    Arrays.fill(plaintext, (byte) 0);
                    throw new EncryptionLimitReachedException(deadline.reason());
                }

                var buffer = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
                var written = provider.encrypt(plaintext, associatedData, buffer);

                // Providers that size exactly (e.g. AES-GCM) need no trim copy; others may over-allocate.
                return written == buffer.length ? buffer : Arrays.copyOf(buffer, written);
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    @Override
    public int decrypt(byte[] ciphertext, byte[] result) {
        return decrypt(ciphertext, EMPTY, result);
    }

    /** {@inheritDoc} Never limited by the deadline. */
    @Override
    public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
        var associatedData = aad == null ? EMPTY : aad;
        var telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        try (var op = telemetry.startSpan(SpanNames.DataProtection.KEY_WRAPPED_KEY_DECRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.DataProtection.KEY_WRAPPED_KEY_DECRYPT,
                        Attributes.of(CIPHERTEXT_LENGTH, (long) ciphertext.length, AAD_LENGTH, (long) associatedData.length));

            try {
                return provider.decrypt(ciphertext, associatedData, result);
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    /** Closes the provider without blocking the caller. Safe to call more than once. */
    public CompletableFuture<Void> closeAsync() {
        return closed.compareAndSet(false, true) ? provider.closeAsync() : CompletableFuture.completedFuture(null);
    }

    /** Closes the provider. Safe to call more than once. */
    @Override
    public void close() {
        if (closed.compareAndSet(false, true))
            provider.close();
    }
}
