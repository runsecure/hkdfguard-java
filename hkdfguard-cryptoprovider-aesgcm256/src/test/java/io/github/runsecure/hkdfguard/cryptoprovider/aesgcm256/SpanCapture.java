package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import java.util.List;

/** Routes HkdfGuard's telemetry to an in-memory exporter until closed. */
final class SpanCapture implements AutoCloseable {
    private final InMemorySpanExporter exporter = InMemorySpanExporter.create();
    private final OpenTelemetrySdk sdk;

    SpanCapture() {
        sdk = OpenTelemetrySdk.builder()
                .setTracerProvider(SdkTracerProvider.builder().addSpanProcessor(SimpleSpanProcessor.create(exporter)).build())
                .build();
        HkdfGuardTelemetry.setOpenTelemetry(sdk);
    }

    /** Every finished span with this name. */
    List<SpanData> spans(String name) {
        return exporter.getFinishedSpanItems().stream().filter(s -> s.getName().equals(name)).toList();
    }

    @Override
    public void close() {
        HkdfGuardTelemetry.setOpenTelemetry(null);
        sdk.close();
    }
}
