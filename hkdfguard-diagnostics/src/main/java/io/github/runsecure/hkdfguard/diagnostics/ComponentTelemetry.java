package io.github.runsecure.hkdfguard.diagnostics;

import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import java.util.Objects;

/**
 * One component's telemetry surface: a {@link Tracer} and {@link Meter} sharing that component's
 * instrumentation scope name, a sensitive-logging toggle, and the
 * {@link #recordException}/{@link #logSensitiveOperation} helpers every operation across the
 * library calls through. A single implementation shared by every component in
 * {@link HkdfGuardTelemetry}.
 * <p>
 * The tracer and meter are resolved from {@link HkdfGuardTelemetry#getOpenTelemetry()} on every
 * call rather than captured once, so an SDK installed after this class loads is still picked up.
 */
public final class ComponentTelemetry {
    private final String sourceName;
    private final ComponentTelemetry sharedFlagOwner;
    private volatile boolean sensitiveLoggingEnabled;

    ComponentTelemetry(String sourceName) {
        this(sourceName, null);
    }

    /**
     * @param sourceName      this component's instrumentation scope name
     * @param sharedFlagOwner the sensitive-logging flag delegates to this component's own flag
     *                        instead of keeping an independent one - e.g. Cache/DataProtection/
     *                        EncryptedConfiguration all share Root's flag; null for an independent flag
     */
    ComponentTelemetry(String sourceName, ComponentTelemetry sharedFlagOwner) {
        this.sourceName = Objects.requireNonNull(sourceName, "sourceName");
        this.sharedFlagOwner = sharedFlagOwner;
    }

    /** This component's instrumentation scope name - e.g. "HkdfGuard.Cache". */
    public String getSourceName() {
        return sourceName;
    }

    /** This component's tracer, from the currently configured OpenTelemetry instance. */
    public Tracer getTracer() {
        return HkdfGuardTelemetry.getOpenTelemetry().getTracer(sourceName);
    }

    /** This component's meter, from the currently configured OpenTelemetry instance. */
    public Meter getMeter() {
        return HkdfGuardTelemetry.getOpenTelemetry().getMeter(sourceName);
    }

    /**
     * Starts a span named {@code spanName} under this component's tracer and makes it current;
     * close the returned scope (try-with-resources) to end it.
     */
    public SpanScope startSpan(String spanName) {
        return SpanScope.start(getTracer().spanBuilder(spanName).startSpan());
    }

    /**
     * When enabled, sensitive operations emit additional debug telemetry (operation metadata such
     * as buffer lengths and identifiers). Raw key, plaintext, and ciphertext bytes are never
     * logged, regardless of this setting. Components constructed with a shared flag owner read and
     * write that owner's flag instead of keeping their own.
     */
    public boolean isSensitiveLoggingEnabled() {
        return sharedFlagOwner != null ? sharedFlagOwner.isSensitiveLoggingEnabled() : sensitiveLoggingEnabled;
    }

    /** See {@link #isSensitiveLoggingEnabled()}. */
    public void setSensitiveLoggingEnabled(boolean enabled) {
        if (sharedFlagOwner != null)
            sharedFlagOwner.setSensitiveLoggingEnabled(enabled);
        else
            sensitiveLoggingEnabled = enabled;
    }

    /** Records an exception on the span and marks it as errored. A null span is ignored. */
    public static void recordException(Span span, Throwable exception) {
        if (span == null)
            return;

        span.recordException(exception);
        span.setStatus(StatusCode.ERROR, String.valueOf(exception.getMessage()));
    }

    /**
     * Emits a fixed-name ({@link EventNames#SENSITIVE_OPERATION}) event on the span when sensitive
     * logging is enabled and the span is recording, carrying operationName and every detail as
     * attributes. Only pass non-sensitive metadata (lengths, identifiers, timings) as details -
     * never raw key, plaintext, or ciphertext bytes.
     */
    public void logSensitiveOperation(Span span, String operationName, Attributes details) {
        if (!isSensitiveLoggingEnabled() || span == null || !span.isRecording())
            return;

        AttributesBuilder attributes = Attributes.builder();
        attributes.put(AttributeNames.OPERATION_NAME, operationName);
        if (details != null)
            attributes.putAll(details);

        span.addEvent(EventNames.SENSITIVE_OPERATION, attributes.build());
    }

    /** {@link #logSensitiveOperation(Span, String, Attributes)} with no details beyond the operation. */
    public void logSensitiveOperation(Span span, String operationName) {
        logSensitiveOperation(span, operationName, Attributes.empty());
    }
}
