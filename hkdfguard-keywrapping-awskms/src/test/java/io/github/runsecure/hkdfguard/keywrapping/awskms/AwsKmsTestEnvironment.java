package io.github.runsecure.hkdfguard.keywrapping.awskms;

import org.junit.jupiter.api.Assumptions;

/**
 * The real KMS key the integration tests run against, if one was given. A test that makes real AWS
 * KMS calls calls {@link #assumeKeyId()} first, so it is reported as skipped unless
 * {@link #KEY_ID_VARIABLE} names a key. Once it does, a failing call is a test failure, never a
 * silent pass.
 */
final class AwsKmsTestEnvironment {
    static final String KEY_ID_VARIABLE = "HKDFGUARD_TEST_AWS_KMS_KEY_ID";

    private AwsKmsTestEnvironment() {
    }

    /** The configured key, or null. */
    static String configuredKeyId() {
        var keyId = System.getenv(KEY_ID_VARIABLE);
        return keyId == null || keyId.isEmpty() ? null : keyId;
    }

    /** The configured key; skips the calling test when there is none. */
    static String assumeKeyId() {
        var keyId = configuredKeyId();
        Assumptions.assumeTrue(keyId != null, "Set " + KEY_ID_VARIABLE + " to a symmetric KMS key to run AWS KMS integration tests.");
        return keyId;
    }
}
