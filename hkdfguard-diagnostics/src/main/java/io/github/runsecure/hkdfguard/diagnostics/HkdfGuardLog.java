package io.github.runsecure.hkdfguard.diagnostics;

import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/**
 * The log messages every component that accepts an SLF4J {@link Logger} shares - the counterpart
 * of the .NET library's HkdfGuardLoggerExtensions, with the same event ids and messages. Each entry
 * carries its event id as the {@link #EVENT_ID_KEY} key-value, so a structured backend can filter
 * on it exactly as on a .NET EventId. A null logger is accepted and ignored.
 * <p>
 * Mirrors logSensitiveOperation/recordException's gating: {@link #sensitiveOperationLogged} is only
 * worth calling when sensitive logging is enabled, while failures are always worth logging.
 */
public final class HkdfGuardLog {
    /** The key-value every entry carries its event id under. */
    public static final String EVENT_ID_KEY = "hkdfguard.event_id";

    /**
     * Marks entries .NET logs at Critical, which SLF4J has no level for: they are logged at ERROR
     * with this marker.
     */
    public static final Marker CRITICAL = MarkerFactory.getMarker("CRITICAL");

    public static final int SENSITIVE_OPERATION_LOGGED = 1;
    public static final int OPERATION_FAILED = 2;
    public static final int KEY_REFRESH_FAILED = 3;
    public static final int KEY_ACCESS_SUSPENDED = 4;
    public static final int KEY_ACCESS_RESUMED = 5;
    public static final int EPHEMERAL_KEY_ROTATED = 6;
    public static final int EPHEMERAL_KEY_ROTATION_FAILED = 7;
    public static final int EPHEMERAL_KEY_RETIRED = 8;
    public static final int EPHEMERAL_KEY_RETIREMENT_FAILED = 9;
    public static final int ENCRYPTION_BUDGET_WARNING = 10;
    public static final int BACKGROUND_TASK_TERMINATED = 11;

    private HkdfGuardLog() {
    }

    /** Debug: an operation completed, named for the value it touched. */
    public static void sensitiveOperationLogged(Logger logger, String operationName, String name) {
        if (logger == null)
            return;

        logger.atDebug()
                .addKeyValue(EVENT_ID_KEY, SENSITIVE_OPERATION_LOGGED)
                .log("{} completed for {}.", operationName, name);
    }

    /** Error: an operation failed. */
    public static void operationFailed(Logger logger, String operationName, Throwable exception) {
        if (logger == null)
            return;

        logger.atError()
                .addKeyValue(EVENT_ID_KEY, OPERATION_FAILED)
                .setCause(exception)
                .log("{} failed.", operationName);
    }

    /**
     * Error: a background attempt to re-reveal a key through its key wrapper failed - the KEK may
     * have been revoked or become unreachable. Logged on every failure, whatever the
     * refresh-failure policy, since under fail-open this is the only sign that the KEK is gone.
     */
    public static void keyRefreshFailed(Logger logger, int consecutiveFailures, String refreshFailurePolicy, Throwable exception) {
        if (logger == null)
            return;

        logger.atError()
                .addKeyValue(EVENT_ID_KEY, KEY_REFRESH_FAILED)
                .setCause(exception)
                .log("Background key refresh failed ({} consecutive). Policy: {}.", consecutiveFailures, refreshFailurePolicy);
    }

    /**
     * Error, marked {@link #CRITICAL}: the refresh-failure limit was reached; the key has been
     * zeroed and every encrypt/decrypt under it throws until a refresh succeeds.
     */
    public static void keyAccessSuspended(Logger logger, int consecutiveFailures) {
        if (logger == null)
            return;

        logger.atError()
                .addMarker(CRITICAL)
                .addKeyValue(EVENT_ID_KEY, KEY_ACCESS_SUSPENDED)
                .log("Key access suspended after {} consecutive failed refreshes; the key has been zeroed and every operation under it fails until a refresh succeeds.",
                        consecutiveFailures);
    }

    /** Info: a refresh succeeded after key access had been suspended; operations resume. */
    public static void keyAccessResumed(Logger logger, int consecutiveFailures) {
        if (logger == null)
            return;

        logger.atInfo()
                .addKeyValue(EVENT_ID_KEY, KEY_ACCESS_RESUMED)
                .log("Key access resumed: a background refresh succeeded after {} consecutive failures.", consecutiveFailures);
    }

    /** Info: a scheduled rotation added a fresh ephemeral key, which is now the current version. */
    public static void ephemeralKeyRotated(Logger logger, int keyVersion) {
        if (logger == null)
            return;

        logger.atInfo()
                .addKeyValue(EVENT_ID_KEY, EPHEMERAL_KEY_ROTATED)
                .log("Ephemeral key rotated: version {} is now current.", keyVersion);
    }

    /**
     * Error: a scheduled rotation could not add a new key; the current version stays in use and
     * the next interval tries again.
     */
    public static void ephemeralKeyRotationFailed(Logger logger, int keyVersion, Throwable exception) {
        if (logger == null)
            return;

        logger.atError()
                .addKeyValue(EVENT_ID_KEY, EPHEMERAL_KEY_ROTATION_FAILED)
                .setCause(exception)
                .log("Ephemeral key rotation failed; version {} stays current until the next attempt.", keyVersion);
    }

    /**
     * Info: a superseded ephemeral key's retention ran out: it has been removed from the ring and
     * closed, so values encrypted under it can no longer be decrypted.
     */
    public static void ephemeralKeyRetired(Logger logger, int keyVersion) {
        if (logger == null)
            return;

        logger.atInfo()
                .addKeyValue(EVENT_ID_KEY, EPHEMERAL_KEY_RETIRED)
                .log("Ephemeral key retired: version {} has been removed and its key zeroed; values encrypted under it no longer decrypt.", keyVersion);
    }

    /** Error: a retired ephemeral key was removed from the ring but closing it threw. */
    public static void ephemeralKeyRetirementFailed(Logger logger, int keyVersion, Throwable exception) {
        if (logger == null)
            return;

        logger.atError()
                .addKeyValue(EVENT_ID_KEY, EPHEMERAL_KEY_RETIREMENT_FAILED)
                .setCause(exception)
                .log("Ephemeral key version {} was removed from the ring, but disposing it failed.", keyVersion);
    }

    /**
     * Warn: a key has performed enough encryptions to cross the warning threshold of its AES-GCM
     * budget; once it reaches the limit it refuses to encrypt, so rotate it before then.
     */
    public static void encryptionBudgetWarning(Logger logger, long encryptionCount, long encryptionLimit) {
        if (logger == null)
            return;

        logger.atWarn()
                .addKeyValue(EVENT_ID_KEY, ENCRYPTION_BUDGET_WARNING)
                .log("This key has performed {} encryptions of its {} AES-GCM limit; rotate it before the limit, when it stops encrypting.",
                        encryptionCount, encryptionLimit);
    }

    /**
     * Error, marked {@link #CRITICAL}: a background task that guards key material (a key refresh,
     * an ephemeral key rotation) ended unexpectedly and will not run again in this process.
     * {@code consequence} says what that means for the keys it looked after.
     */
    public static void backgroundTaskTerminated(Logger logger, String taskName, String consequence, Throwable exception) {
        if (logger == null)
            return;

        logger.atError()
                .addMarker(CRITICAL)
                .addKeyValue(EVENT_ID_KEY, BACKGROUND_TASK_TERMINATED)
                .setCause(exception)
                .log("The {} stopped unexpectedly and will not run again until the process restarts. {}", taskName, consequence);
    }
}
