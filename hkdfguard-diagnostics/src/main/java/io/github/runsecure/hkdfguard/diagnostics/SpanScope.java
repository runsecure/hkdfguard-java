package io.github.runsecure.hkdfguard.diagnostics;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.context.Scope;

/**
 * A started span made current for the duration of one operation - the Java counterpart of .NET's
 * {@code using var activity = source.StartActivity(...)}. Close it (try-with-resources) to restore
 * the previous context and end the span.
 */
public final class SpanScope implements AutoCloseable {
    private final Span span;
    private final Scope scope;

    private SpanScope(Span span, Scope scope) {
        this.span = span;
        this.scope = scope;
    }

    static SpanScope start(Span span) {
        return new SpanScope(span, span.makeCurrent());
    }

    /** The span this scope started; never null, though it may not be recording. */
    public Span span() {
        return span;
    }

    /** {@link ComponentTelemetry#recordException} on this scope's span. */
    public void recordException(Throwable exception) {
        ComponentTelemetry.recordException(span, exception);
    }

    @Override
    public void close() {
        scope.close();
        span.end();
    }
}
