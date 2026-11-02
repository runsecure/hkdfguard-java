package io.github.runsecure.hkdfguard.diagnostics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.LongPointData;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.Map;
import org.slf4j.event.Level;

class CacheMetricsAndLoggerTest {
    @Test
    void cacheMetricsOperations_ReportsMeasurementsWithTheirTags_OnTheCacheMeter() {
        var reader = InMemoryMetricReader.create();
        var sdk = OpenTelemetrySdk.builder().setMeterProvider(SdkMeterProvider.builder().registerMetricReader(reader).build()).build();
        HkdfGuardTelemetry.setOpenTelemetry(sdk);
        try {
            CacheMetrics.operations().add(1, Attributes.of(AttributeKey.stringKey(AttributeNames.RESULT), "success"));

            var metric = reader.collectAllMetrics().stream()
                    .filter(m -> m.getName().equals(MetricNames.Cache.OPERATIONS))
                    .findFirst().orElseThrow();
            assertEquals(HkdfGuardTelemetry.CACHE.getSourceName(), metric.getInstrumentationScopeInfo().getName());
            assertEquals(CacheMetrics.OPERATIONS_UNIT, metric.getUnit());
            LongPointData point = metric.getLongSumData().getPoints().iterator().next();
            assertEquals(1, point.getValue());
            assertEquals("success", point.getAttributes().get(AttributeKey.stringKey(AttributeNames.RESULT)));
        } finally {
            HkdfGuardTelemetry.setOpenTelemetry(null);
            sdk.close();
        }
    }

    @Test
    void cacheMetricsOperations_FollowsAnSdkInstalledAfterFirstUse() {
        CacheMetrics.operations().add(1); // no SDK yet: a no-op
        var reader = InMemoryMetricReader.create();
        var sdk = OpenTelemetrySdk.builder().setMeterProvider(SdkMeterProvider.builder().registerMetricReader(reader).build()).build();
        HkdfGuardTelemetry.setOpenTelemetry(sdk);
        try {
            CacheMetrics.operations().add(2);

            assertSame(CacheMetrics.operations(), CacheMetrics.operations());
            assertTrue(reader.collectAllMetrics().stream()
                    .anyMatch(m -> m.getName().equals(MetricNames.Cache.OPERATIONS)
                            && m.getLongSumData().getPoints().iterator().next().getValue() == 2));
        } finally {
            HkdfGuardTelemetry.setOpenTelemetry(null);
            sdk.close();
        }
    }

    @Test
    void sensitiveOperationLogged_WritesADebugEntryNamingTheOperationAndName() {
        var logger = new RecordingLogger();

        HkdfGuardLog.sensitiveOperationLogged(logger, "hkdfguard.cache.add", "item");

        var entry = single(logger);
        assertEquals(Level.DEBUG, entry.level());
        assertEquals(1, entry.eventId());
        assertEquals("hkdfguard.cache.add completed for item.", entry.message());
    }

    @Test
    void operationFailed_WritesAnErrorEntryCarryingTheException() {
        var logger = new RecordingLogger();
        var failure = new IllegalStateException("boom");

        HkdfGuardLog.operationFailed(logger, "hkdfguard.cache.add", failure);

        var entry = single(logger);
        assertEquals(Level.ERROR, entry.level());
        assertEquals(2, entry.eventId());
        assertEquals("hkdfguard.cache.add failed.", entry.message());
        assertSame(failure, entry.exception());
    }

    @Test
    void keyRefreshFailed_WritesAnErrorEntryWithTheCountPolicyAndException() {
        var logger = new RecordingLogger();
        var failure = new IllegalStateException("KEK unavailable");

        HkdfGuardLog.keyRefreshFailed(logger, 2, "fail closed after 3 consecutive failures", failure);

        var entry = single(logger);
        assertEquals(Level.ERROR, entry.level());
        assertEquals(3, entry.eventId());
        assertEquals("Background key refresh failed (2 consecutive). Policy: fail closed after 3 consecutive failures.", entry.message());
        assertSame(failure, entry.exception());
    }

    @Test
    void keyAccessSuspended_WritesAnErrorEntryMarkedCritical() {
        var logger = new RecordingLogger();

        HkdfGuardLog.keyAccessSuspended(logger, 3);

        var entry = single(logger);
        assertEquals(Level.ERROR, entry.level());
        assertTrue(entry.markers().contains(HkdfGuardLog.CRITICAL));
        assertEquals(4, entry.eventId());
        assertTrue(entry.message().startsWith("Key access suspended after 3 consecutive failed refreshes"));
    }

    @Test
    void keyAccessResumed_WritesAnInformationEntry() {
        var logger = new RecordingLogger();

        HkdfGuardLog.keyAccessResumed(logger, 4);

        var entry = single(logger);
        assertEquals(Level.INFO, entry.level());
        assertEquals(5, entry.eventId());
        assertEquals("Key access resumed: a background refresh succeeded after 4 consecutive failures.", entry.message());
    }

    @Test
    void ephemeralKeyRotated_WritesAnInformationEntryNamingTheNewVersion() {
        var logger = new RecordingLogger();

        HkdfGuardLog.ephemeralKeyRotated(logger, 8);

        var entry = single(logger);
        assertEquals(Level.INFO, entry.level());
        assertEquals(6, entry.eventId());
        assertEquals("Ephemeral key rotated: version 8 is now current.", entry.message());
    }

    @Test
    void ephemeralKeyRotationFailed_WritesAnErrorEntryNamingTheVersionStillCurrent() {
        var logger = new RecordingLogger();
        var failure = new IllegalStateException("KEK unavailable");

        HkdfGuardLog.ephemeralKeyRotationFailed(logger, 7, failure);

        var entry = single(logger);
        assertEquals(Level.ERROR, entry.level());
        assertEquals(7, entry.eventId());
        assertEquals("Ephemeral key rotation failed; version 7 stays current until the next attempt.", entry.message());
        assertSame(failure, entry.exception());
    }

    @Test
    void ephemeralKeyRetiredAndRetirementFailed_CarryTheirEventIds() {
        var logger = new RecordingLogger();

        HkdfGuardLog.ephemeralKeyRetired(logger, 2);
        HkdfGuardLog.ephemeralKeyRetirementFailed(logger, 3, new IllegalStateException());
        HkdfGuardLog.encryptionBudgetWarning(logger, 2, 10);

        var entries = logger.entries();
        assertEquals(8, entries.get(0).eventId());
        assertEquals(9, entries.get(1).eventId());
        assertEquals(10, entries.get(2).eventId());
        assertEquals(Level.WARN, entries.get(2).level());
        assertTrue(entries.get(2).message().contains("2 encryptions of its 10"));
    }

    @Test
    void keyFileAgeWarning_WritesAWarningNamingTheFileVersionAndDeadline() {
        var logger = new RecordingLogger();

        HkdfGuardLog.keyFileAgeWarning(logger, 3, "/etc/dek-v3.bin", Instant.parse("2027-01-02T03:04:05Z"));

        var entry = single(logger);
        assertEquals(Level.WARN, entry.level());
        assertEquals(12, entry.eventId());
        assertEquals("Key file '/etc/dek-v3.bin' (version 3) stops encrypting at 2027-01-02T03:04:05.000Z, when it reaches its maximum age; "
                + "deploy a new key file at a higher version before then.", entry.message());
        assertEquals(Map.of(HkdfGuardLog.EVENT_ID_KEY, 12, AttributeNames.KEY_VERSION, 3, AttributeNames.KEY_FILE_PATH, "/etc/dek-v3.bin"),
                entry.keyValues());
    }

    @Test
    void keyFileExpired_WritesAnErrorEntryMarkedCritical() {
        var logger = new RecordingLogger();

        HkdfGuardLog.keyFileExpired(logger, 3, "/etc/dek-v3.bin");

        var entry = single(logger);
        assertEquals(Level.ERROR, entry.level());
        assertTrue(entry.markers().contains(HkdfGuardLog.CRITICAL));
        assertEquals(13, entry.eventId());
        assertEquals("Key file '/etc/dek-v3.bin' (version 3) has passed its maximum age and no longer encrypts; values under it still decrypt. "
                + "Deploy a new key file at a higher version.", entry.message());
        assertEquals(Map.of(HkdfGuardLog.EVENT_ID_KEY, 13, AttributeNames.KEY_VERSION, 3, AttributeNames.KEY_FILE_PATH, "/etc/dek-v3.bin"),
                entry.keyValues());
    }

    @Test
    void logMessages_WhenTheLevelIsDisabled_WriteNothing() {
        var logger = new RecordingLogger(false);

        HkdfGuardLog.sensitiveOperationLogged(logger, "hkdfguard.cache.add", "item");
        HkdfGuardLog.operationFailed(logger, "hkdfguard.cache.add", new IllegalStateException());
        HkdfGuardLog.keyRefreshFailed(logger, 1, "fail open", new IllegalStateException());
        HkdfGuardLog.keyAccessSuspended(logger, 1);
        HkdfGuardLog.keyAccessResumed(logger, 1);
        HkdfGuardLog.ephemeralKeyRotated(logger, 1);
        HkdfGuardLog.ephemeralKeyRotationFailed(logger, 1, new IllegalStateException());
        HkdfGuardLog.keyFileAgeWarning(logger, 1, "k.bin", Instant.EPOCH);
        HkdfGuardLog.keyFileExpired(logger, 1, "k.bin");

        assertTrue(logger.entries().isEmpty());
    }

    @Test
    void logMessages_WithANullLogger_DoNothing() {
        assertDoesNotThrow(() -> HkdfGuardLog.keyAccessSuspended(null, 1));
        assertDoesNotThrow(() -> HkdfGuardLog.operationFailed(null, "op", new IllegalStateException()));
        assertDoesNotThrow(() -> HkdfGuardLog.keyFileExpired(null, 1, "k.bin"));
    }

    private static RecordingLogger.Entry single(RecordingLogger logger) {
        var entries = logger.entries();
        assertEquals(1, entries.size());
        return entries.getFirst();
    }
}
