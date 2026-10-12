package io.github.runsecure.hkdfguard.diagnostics;

/**
 * Attribute keys shared across every component's spans, events, and metrics - lowercase,
 * dot-separated (OpenTelemetry semantic-convention style), identical to every other port's.
 */
public final class AttributeNames {
    public static final String NAME = "hkdfguard.name";
    public static final String PLAINTEXT_LENGTH = "hkdfguard.plaintext_length";
    public static final String CIPHERTEXT_LENGTH = "hkdfguard.ciphertext_length";
    public static final String ENCRYPTED_LENGTH = "hkdfguard.encrypted_length";
    public static final String AAD_LENGTH = "hkdfguard.aad_length";
    public static final String VALUE_LENGTH = "hkdfguard.value_length";
    public static final String KEY_VERSION = "hkdfguard.key_version";
    public static final String KEY_RING_BECAME_CURRENT = "hkdfguard.key_ring.became_current";
    public static final String OPERATION_NAME = "hkdfguard.operation.name";
    public static final String RESULT = "hkdfguard.result";
    public static final String ENCRYPTION_COUNT = "hkdfguard.encryption_count";
    public static final String ENCRYPTION_LIMIT = "hkdfguard.encryption_limit";
    public static final String CONSECUTIVE_FAILURES = "hkdfguard.consecutive_failures";

    private AttributeNames() {
    }
}
