package io.github.runsecure.hkdfguard.diagnostics;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.metrics.LongCounter;

/**
 * Cache component instruments, built on {@link HkdfGuardTelemetry#CACHE}'s meter. Operations counts
 * every ProtectedCache add/addOrUpdate call and every fetch a populating cache (e.g. the Azure Key
 * Vault, AWS Secrets Manager, Google Secret Manager and HashiCorp Vault secret caches) makes on a
 * miss, tagged with {@link AttributeNames#OPERATION_NAME} (which {@link SpanNames.Cache} constant
 * ran) and {@link AttributeNames#RESULT} ("success" or "error", or "not_found" for a fetch whose
 * source has no such value).
 */
public final class CacheMetrics {
    public static final String OPERATIONS_UNIT = "{operation}";

    public static final String OPERATIONS_DESCRIPTION = "Number of ProtectedCache operations, tagged by operation and result.";

    // The counter for the OpenTelemetry instance it was built from; rebuilt if that changes, so an
    // SDK installed later is picked up.
    private static volatile Instrument operations;

    private record Instrument(OpenTelemetry source, LongCounter counter) {
    }

    private CacheMetrics() {
    }

    /** The {@link MetricNames.Cache#OPERATIONS} counter. */
    public static LongCounter operations() {
        var current = HkdfGuardTelemetry.getOpenTelemetry();
        var cached = operations;
        if (cached != null && cached.source() == current)
            return cached.counter();

        var counter = HkdfGuardTelemetry.CACHE.getMeter()
                .counterBuilder(MetricNames.Cache.OPERATIONS)
                .setUnit(OPERATIONS_UNIT)
                .setDescription(OPERATIONS_DESCRIPTION)
                .build();
        operations = new Instrument(current, counter);
        return counter;
    }
}
