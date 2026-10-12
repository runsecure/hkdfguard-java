package io.github.runsecure.hkdfguard.dataencryptionkey;

import io.github.runsecure.hkdfguard.abstractions.CryptoProvider;
import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
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
 */
public final class DataEncryptionKeyImpl implements DataEncryptionKey, AutoCloseable {
    private static final byte[] EMPTY = new byte[0];
    private static final AttributeKey<Long> PLAINTEXT_LENGTH = AttributeKey.longKey(AttributeNames.PLAINTEXT_LENGTH);
    private static final AttributeKey<Long> CIPHERTEXT_LENGTH = AttributeKey.longKey(AttributeNames.CIPHERTEXT_LENGTH);
    private static final AttributeKey<Long> AAD_LENGTH = AttributeKey.longKey(AttributeNames.AAD_LENGTH);

    private final CryptoProvider provider;
    private final AtomicBoolean closed = new AtomicBoolean();

    /** @param provider owned by this key from here on */
    public DataEncryptionKeyImpl(CryptoProvider provider) {
        this.provider = Objects.requireNonNull(provider, "provider");
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        return encrypt(plaintext, EMPTY);
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) {
        var associatedData = aad == null ? EMPTY : aad;
        var telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        try (var op = telemetry.startSpan(SpanNames.DataProtection.KEY_WRAPPED_KEY_ENCRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.DataProtection.KEY_WRAPPED_KEY_ENCRYPT,
                        Attributes.of(PLAINTEXT_LENGTH, (long) plaintext.length, AAD_LENGTH, (long) associatedData.length));

            try {
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
