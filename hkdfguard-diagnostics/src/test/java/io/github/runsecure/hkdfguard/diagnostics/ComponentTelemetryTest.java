package io.github.runsecure.hkdfguard.diagnostics;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class ComponentTelemetryTest {
    private InMemorySpanExporter exporter;
    private OpenTelemetrySdk sdk;

    static Stream<ComponentTelemetry> allComponents() {
        return Stream.of(HkdfGuardTelemetry.ROOT, HkdfGuardTelemetry.CACHE, HkdfGuardTelemetry.DATA_PROTECTION,
                HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION, HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256,
                HkdfGuardTelemetry.KEY_WRAPPING);
    }

    @BeforeEach
    void installSdk() {
        exporter = InMemorySpanExporter.create();
        sdk = OpenTelemetrySdk.builder()
                .setTracerProvider(SdkTracerProvider.builder().addSpanProcessor(SimpleSpanProcessor.create(exporter)).build())
                .build();
        HkdfGuardTelemetry.setOpenTelemetry(sdk);
    }

    @AfterEach
    void removeSdk() {
        HkdfGuardTelemetry.setOpenTelemetry(null);
        sdk.close();
    }

    @ParameterizedTest
    @MethodSource("allComponents")
    void spans_AreReportedUnderTheComponentsScopeName(ComponentTelemetry component) {
        try (var ignored = component.startSpan("test-span")) {
            // nothing
        }

        assertEquals(component.getSourceName(), single().getInstrumentationScopeInfo().getName());
    }

    @Test
    void recordException_WithNullSpan_DoesNotThrow() {
        assertDoesNotThrow(() -> ComponentTelemetry.recordException(null, new IllegalStateException("boom")));
    }

    @ParameterizedTest
    @MethodSource("allComponents")
    void recordException_WithARealSpan_RecordsExceptionAndErrorStatus(ComponentTelemetry component) {
        try (var scope = component.startSpan("test-span")) {
            scope.recordException(new IllegalStateException("boom"));
        }

        var span = single();
        assertEquals(StatusCode.ERROR, span.getStatus().getStatusCode());
        assertEquals("boom", span.getStatus().getDescription());
        assertTrue(span.getEvents().stream().anyMatch(e -> e.getName().equals("exception")));
    }

    @ParameterizedTest
    @MethodSource("allComponents")
    void logSensitiveOperation_WithNullOrNonRecordingSpan_DoesNotThrow(ComponentTelemetry component) {
        assertDoesNotThrow(() -> component.logSensitiveOperation(null, "test-op"));
        assertDoesNotThrow(() -> component.logSensitiveOperation(Span.getInvalid(), "test-op"));
    }

    @ParameterizedTest
    @MethodSource("allComponents")
    void logSensitiveOperation_WhenDisabled_DoesNotAddEvent(ComponentTelemetry component) {
        var original = component.isSensitiveLoggingEnabled();
        try {
            component.setSensitiveLoggingEnabled(false);
            try (var scope = component.startSpan("test-span")) {
                component.logSensitiveOperation(scope.span(), "test-op", Attributes.of(AttributeKey.stringKey("key"), "value"));
            }

            assertTrue(single().getEvents().isEmpty());
        } finally {
            component.setSensitiveLoggingEnabled(original);
        }
    }

    @ParameterizedTest
    @MethodSource("allComponents")
    void logSensitiveOperation_WhenEnabled_AddsFixedNameEventWithOperationAndDetailAttributes(ComponentTelemetry component) {
        var original = component.isSensitiveLoggingEnabled();
        try {
            component.setSensitiveLoggingEnabled(true);
            try (var scope = component.startSpan("test-span")) {
                component.logSensitiveOperation(scope.span(), "test-op", Attributes.of(AttributeKey.stringKey(AttributeNames.NAME), "item"));
            }

            var events = single().getEvents();
            assertEquals(1, events.size());
            var event = events.getFirst();
            assertEquals(EventNames.SENSITIVE_OPERATION, event.getName());
            assertEquals("test-op", event.getAttributes().get(AttributeKey.stringKey(AttributeNames.OPERATION_NAME)));
            assertEquals("item", event.getAttributes().get(AttributeKey.stringKey(AttributeNames.NAME)));
        } finally {
            component.setSensitiveLoggingEnabled(original);
        }
    }

    @Test
    void sensitiveLogging_RootSharesItsFlagWithCacheDataProtectionAndEncryptedConfiguration() {
        var original = HkdfGuardTelemetry.ROOT.isSensitiveLoggingEnabled();
        try {
            HkdfGuardTelemetry.ROOT.setSensitiveLoggingEnabled(true);
            assertTrue(HkdfGuardTelemetry.CACHE.isSensitiveLoggingEnabled());
            assertTrue(HkdfGuardTelemetry.DATA_PROTECTION.isSensitiveLoggingEnabled());
            assertTrue(HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION.isSensitiveLoggingEnabled());

            HkdfGuardTelemetry.CACHE.setSensitiveLoggingEnabled(false);
            assertFalse(HkdfGuardTelemetry.ROOT.isSensitiveLoggingEnabled());
            assertFalse(HkdfGuardTelemetry.DATA_PROTECTION.isSensitiveLoggingEnabled());
            assertFalse(HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION.isSensitiveLoggingEnabled());
        } finally {
            HkdfGuardTelemetry.ROOT.setSensitiveLoggingEnabled(original);
        }
    }

    @Test
    void sensitiveLogging_CryptoProviderAesGcm256AndKeyWrapping_AreIndependentFromRootAndEachOther() {
        var originalRoot = HkdfGuardTelemetry.ROOT.isSensitiveLoggingEnabled();
        var originalCrypto = HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.isSensitiveLoggingEnabled();
        var originalKeyWrapping = HkdfGuardTelemetry.KEY_WRAPPING.isSensitiveLoggingEnabled();
        try {
            HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.setSensitiveLoggingEnabled(false);
            HkdfGuardTelemetry.KEY_WRAPPING.setSensitiveLoggingEnabled(false);

            HkdfGuardTelemetry.ROOT.setSensitiveLoggingEnabled(true);
            assertFalse(HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.isSensitiveLoggingEnabled());
            assertFalse(HkdfGuardTelemetry.KEY_WRAPPING.isSensitiveLoggingEnabled());

            HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.setSensitiveLoggingEnabled(true);
            assertFalse(HkdfGuardTelemetry.KEY_WRAPPING.isSensitiveLoggingEnabled());
        } finally {
            HkdfGuardTelemetry.ROOT.setSensitiveLoggingEnabled(originalRoot);
            HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256.setSensitiveLoggingEnabled(originalCrypto);
            HkdfGuardTelemetry.KEY_WRAPPING.setSensitiveLoggingEnabled(originalKeyWrapping);
        }
    }

    @Test
    void withoutAConfiguredInstance_TelemetryIsANoOpAndNeverLatchesTheGlobal() {
        HkdfGuardTelemetry.setOpenTelemetry(null);

        try (var scope = HkdfGuardTelemetry.ROOT.startSpan("unrecorded")) {
            assertFalse(scope.span().isRecording());
        }
        assertFalse(io.opentelemetry.api.GlobalOpenTelemetry.isSet());
    }

    private SpanData single() {
        var spans = exporter.getFinishedSpanItems();
        assertEquals(1, spans.size());
        return spans.getFirst();
    }
}
