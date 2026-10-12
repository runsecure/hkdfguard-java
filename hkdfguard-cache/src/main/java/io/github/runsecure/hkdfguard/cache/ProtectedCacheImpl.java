package io.github.runsecure.hkdfguard.cache;

import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.abstractions.ProtectedCache;
import io.github.runsecure.hkdfguard.abstractions.ProtectedCacheBase;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.CacheMetrics;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The default {@link ProtectedCache}, backed by a {@link KeyRing}: every add/addOrUpdate encrypts
 * under the ring's current key and records its version, and every decrypt reveals under the version
 * the entry recorded (see {@link ProtectedCacheBase}), so the cache follows key rotation while values
 * stored earlier stay readable. add's insert-if-absent is atomic, so a duplicate name is rejected
 * even under concurrent callers; addOrUpdate and decrypt are otherwise lock-free. Nothing here ever
 * holds plaintext beyond the duration of a single call.
 * <p>
 * Every add/addOrUpdate counts toward {@link CacheMetrics#operations()}, tagged with the operation
 * and its result. The logger receives a debug entry per operation while sensitive logging is
 * enabled, and an error entry per failure.
 */
public final class ProtectedCacheImpl extends ProtectedCacheBase implements ProtectedCache {
    private static final AttributeKey<String> NAME = AttributeKey.stringKey(AttributeNames.NAME);
    private static final AttributeKey<Long> PLAINTEXT_LENGTH = AttributeKey.longKey(AttributeNames.PLAINTEXT_LENGTH);
    private static final AttributeKey<String> OPERATION_NAME = AttributeKey.stringKey(AttributeNames.OPERATION_NAME);
    private static final AttributeKey<String> RESULT = AttributeKey.stringKey(AttributeNames.RESULT);

    private final Logger logger;

    /**
     * A cache logging through this class's SLF4J logger.
     *
     * @param keyRing supplies the current key for every add and the recorded version's key for every
     *                decrypt; owned by the caller - the cache never closes keys
     */
    public ProtectedCacheImpl(KeyRing keyRing) {
        this(keyRing, null);
    }

    /**
     * @param keyRing see {@link #ProtectedCacheImpl(KeyRing)}
     * @param logger  receives debug entries for sensitive operations and errors for failures; null
     *                for this class's SLF4J logger
     */
    public ProtectedCacheImpl(KeyRing keyRing, Logger logger) {
        super(keyRing);
        this.logger = logger != null ? logger : LoggerFactory.getLogger(ProtectedCacheImpl.class);
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException     name or plaintext is null
     * @throws IllegalArgumentException a value is already stored under this name (ignoring ASCII
     *                                  case), plaintext is empty, or name is not valid UTF-16
     */
    @Override
    public void add(String name, byte[] plaintext) {
        run(SpanNames.Cache.ADD, name, plaintext == null ? 0 : plaintext.length, () -> encrypt(name, plaintext), true);
    }

    /** {@inheritDoc} See {@link #add(String, byte[])} for what is refused. */
    @Override
    public void add(String name, char[] plaintext) {
        run(SpanNames.Cache.ADD, name, plaintext == null ? 0 : plaintext.length, () -> encryptChars(name, plaintext), true);
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException     name or plaintext is null
     * @throws IllegalArgumentException plaintext is empty, or name is not valid UTF-16
     */
    @Override
    public void addOrUpdate(String name, byte[] plaintext) {
        run(SpanNames.Cache.ADD_OR_UPDATE, name, plaintext == null ? 0 : plaintext.length, () -> encrypt(name, plaintext), false);
    }

    /** {@inheritDoc} See {@link #addOrUpdate(String, byte[])} for what is refused. */
    @Override
    public void addOrUpdate(String name, char[] plaintext) {
        run(SpanNames.Cache.ADD_OR_UPDATE, name, plaintext == null ? 0 : plaintext.length, () -> encryptChars(name, plaintext), false);
    }

    private void run(String operation, String name, int plaintextLength, Supplier<KeyTrackingValue> encrypt, boolean onlyIfAbsent) {
        var telemetry = HkdfGuardTelemetry.CACHE;
        try (var op = telemetry.startSpan(operation)) {
            if (telemetry.isSensitiveLoggingEnabled()) {
                telemetry.logSensitiveOperation(op.span(), operation, Attributes.of(NAME, String.valueOf(name), PLAINTEXT_LENGTH, (long) plaintextLength));
                HkdfGuardLog.sensitiveOperationLogged(logger, operation, name);
            }

            try {
                // Encrypting zeroes the plaintext on every path, a null name included.
                var entry = encrypt.get();
                if (onlyIfAbsent) {
                    if (!putEntryIfAbsent(name, entry))
                        throw new IllegalArgumentException("An item with the name '" + name + "' has already been added.");
                } else {
                    putEntry(name, entry);
                }
                recordOperation(operation, true);
            } catch (RuntimeException e) {
                op.recordException(e);
                HkdfGuardLog.operationFailed(logger, operation, e);
                recordOperation(operation, false);
                throw e;
            }
        }
    }

    private static void recordOperation(String operation, boolean success) {
        CacheMetrics.operations().add(1, Attributes.of(OPERATION_NAME, operation, RESULT, success ? "success" : "error"));
    }
}
