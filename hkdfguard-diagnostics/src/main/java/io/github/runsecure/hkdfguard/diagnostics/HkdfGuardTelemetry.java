package io.github.runsecure.hkdfguard.diagnostics;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.OpenTelemetry;

/**
 * One {@link ComponentTelemetry} instance per component in the library. Root, Cache,
 * DataProtection, and EncryptedConfiguration all share one sensitive-logging flag (set any of them,
 * all four read the new value); CryptoProviderAesGcm256 and KeyWrapping each keep their own,
 * independent flag.
 * <p>
 * Telemetry goes to {@link GlobalOpenTelemetry} unless {@link #setOpenTelemetry} names another
 * instance. It is read without ever registering a no-op global, so an application may install its
 * SDK at any point, before or after HkdfGuard is first used.
 */
public final class HkdfGuardTelemetry {
    public static final ComponentTelemetry ROOT = new ComponentTelemetry("HkdfGuard");

    public static final ComponentTelemetry CACHE = new ComponentTelemetry("HkdfGuard.Cache", ROOT);

    public static final ComponentTelemetry DATA_PROTECTION = new ComponentTelemetry("HkdfGuard.DataEncryptionKey", ROOT);

    public static final ComponentTelemetry ENCRYPTED_CONFIGURATION = new ComponentTelemetry("HkdfGuard.EncryptedConfiguration", ROOT);

    public static final ComponentTelemetry CRYPTO_PROVIDER_AES_GCM256 = new ComponentTelemetry("HkdfGuard.CryptoProvider.AesGcm256");

    public static final ComponentTelemetry KEY_WRAPPING = new ComponentTelemetry("HkdfGuard.KeyWrapping.V1");

    private static volatile OpenTelemetry openTelemetry;

    private HkdfGuardTelemetry() {
    }

    /**
     * The OpenTelemetry instance every component reports to: the one given to
     * {@link #setOpenTelemetry}, otherwise the global one (a no-op until the application registers
     * an SDK).
     */
    public static OpenTelemetry getOpenTelemetry() {
        var configured = openTelemetry;
        return configured != null ? configured : GlobalOpenTelemetry.getOrNoop();
    }

    /**
     * Sends every component's telemetry to {@code instance} instead of the global OpenTelemetry;
     * null reverts to the global one.
     */
    public static void setOpenTelemetry(OpenTelemetry instance) {
        openTelemetry = instance;
    }
}
