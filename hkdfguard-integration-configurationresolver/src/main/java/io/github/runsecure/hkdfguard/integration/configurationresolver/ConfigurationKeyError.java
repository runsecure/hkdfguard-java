package io.github.runsecure.hkdfguard.integration.configurationresolver;

/** Why a configuration item could not be resolved. */
public enum ConfigurationKeyError {
    /** The key was not read by the configuration item reader, so the value provider was not asked for it. */
    NOT_ALLOWED,

    /** The key was allowed, but the value provider has no value for it. */
    NOT_FOUND,

    /** The value kept changing size while it was read, such as a secret file being rewritten. */
    VALUE_UNSTABLE,

    /** The key's value, resolved through the items in it, leads back to the same key. */
    CYCLE,
}
