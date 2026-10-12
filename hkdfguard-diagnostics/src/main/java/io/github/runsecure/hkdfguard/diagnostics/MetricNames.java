package io.github.runsecure.hkdfguard.diagnostics;

/**
 * Metric instrument names, following the same {@code hkdfguard.<component>.<noun>} convention as
 * {@link SpanNames}.
 */
public final class MetricNames {
    private MetricNames() {
    }

    public static final class Cache {
        public static final String OPERATIONS = "hkdfguard.cache.operations";

        private Cache() {
        }
    }
}
