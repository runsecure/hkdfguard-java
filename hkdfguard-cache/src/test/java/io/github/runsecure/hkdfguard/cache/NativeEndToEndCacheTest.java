package io.github.runsecure.hkdfguard.cache;

import static io.github.runsecure.hkdfguard.cache.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The runtime keys a process generates for itself through the real native KEK, protecting values
 * and a cache - the .NET port's NativeEndToEndTests.RuntimeKeys_GeneratedThroughTheNativeKek_ProtectValuesAndTheCache,
 * here because the cache module is the one that sees both the key ring and the cache. Runs against
 * HKDFGUARD_TEST_SERVICE, or on Windows the provisioned test KEK com.hkdfguard.integration.test.221;
 * reported as skipped where there is none (as hkdfguard-dataencryptionkey's NativeEndToEndTest).
 */
class NativeEndToEndCacheTest {
    private static String service;

    @BeforeAll
    static void requireAProvisionedService() {
        var explicit = System.getenv("HKDFGUARD_TEST_SERVICE");
        if (explicit != null && !explicit.isEmpty()) {
            service = explicit;
            return;
        }

        Assumptions.assumeTrue(System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows"),
                "Set HKDFGUARD_TEST_SERVICE to a provisioned service to run native end-to-end tests.");
        var candidate = "com.hkdfguard.integration.test.221";
        try {
            new NativeHkdfKeyWrapperV1Impl(candidate).generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]).get();
        } catch (ExecutionException | InterruptedException e) {
            var message = String.valueOf(e.getCause() == null ? e : e.getCause().getMessage());
            // Not installed, not provisioned, or not permitted: skip. Anything else is a real failure.
            Assumptions.assumeFalse(message.contains("not installed") || message.contains("status -17") || message.contains("status -18"),
                    "The Windows test KEK is unavailable: " + message
                            + " Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, or set HKDFGUARD_TEST_SERVICE to a provisioned service.");
        }
        service = candidate;
    }

    @Test
    void runtimeKeys_GeneratedThroughTheNativeKek_ProtectValuesAndTheCache() {
        try (var ring = await(new KeyRingBuilder()
                .withServiceName(service)
                .withKeyWrapper(new NativeHkdfKeyWrapperV1Impl(service))
                .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
                .withKeyRefreshInterval(60)
                .withEphemeralKey(100)
                .buildAsync())) {
            var protector = ring.createProtector("session");
            var formatted = protector.encrypt("runtime value");
            assertTrue(formatted.startsWith("enc::v100::"), formatted);
            var result = new char[protector.getMaxDecryptedLength(formatted)];
            assertEquals("runtime value", new String(result, 0, protector.decrypt(formatted, result)));

            var cache = new ProtectedCacheImpl(ring);
            cache.add("token", "cached secret".toCharArray());
            var revealed = new char[cache.findMaxDecryptedLength("token").orElseThrow()];
            assertEquals("cached secret", new String(revealed, 0, cache.decrypt("token", revealed)));
        }
    }
}
