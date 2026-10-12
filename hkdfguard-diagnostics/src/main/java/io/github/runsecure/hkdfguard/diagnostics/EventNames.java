package io.github.runsecure.hkdfguard.diagnostics;

/**
 * Fixed span event names. Unlike the operation-specific {@link SpanNames}, an event's own name
 * stays constant regardless of which operation raised it - the operation itself is carried as the
 * {@link AttributeNames#OPERATION_NAME} attribute instead - so event names stay low-cardinality
 * and stable for dashboards/queries.
 */
public final class EventNames {
    public static final String SENSITIVE_OPERATION = "hkdfguard.sensitive_operation";

    /**
     * Raised once, on the encrypt span that crosses a key's encryption-count warning threshold -
     * carries {@link AttributeNames#ENCRYPTION_COUNT} and {@link AttributeNames#ENCRYPTION_LIMIT}.
     */
    public static final String ENCRYPTION_BUDGET_WARNING = "hkdfguard.encryption_budget_warning";

    /**
     * Raised on the background-refresh span whose failure reached the configured consecutive-
     * failure limit: the provider has closed its sessions (zeroing the DEK) and suspended
     * encrypt/decrypt until a refresh succeeds. Carries {@link AttributeNames#CONSECUTIVE_FAILURES}.
     */
    public static final String KEY_ACCESS_SUSPENDED = "hkdfguard.key_access_suspended";

    private EventNames() {
    }
}
