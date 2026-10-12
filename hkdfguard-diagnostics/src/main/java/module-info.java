/**
 * HkdfGuard's telemetry: one {@link io.github.runsecure.hkdfguard.diagnostics.ComponentTelemetry}
 * per component, the span, attribute, event and metric names every component emits, and the
 * SLF4J log messages they share.
 */
module io.github.runsecure.hkdfguard.diagnostics {
    requires transitive io.opentelemetry.api;
    requires transitive io.opentelemetry.context;
    requires transitive org.slf4j;

    exports io.github.runsecure.hkdfguard.diagnostics;
}
