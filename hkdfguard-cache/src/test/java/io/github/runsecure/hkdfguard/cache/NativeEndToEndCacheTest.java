package io.github.runsecure.hkdfguard.cache;

import static io.github.runsecure.hkdfguard.cache.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.NativeTestEnvironment;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The runtime keys a process generates for itself through the real native KEK, protecting values
 * and a cache - the .NET port's NativeEndToEndTests.RuntimeKeys_GeneratedThroughTheNativeKek_ProtectValuesAndTheCache,
 * here because the cache module is the one that sees both the key ring and the cache. Runs against
 * the service NativeTestEnvironment.assumeService chooses - HKDFGUARD_TEST_SERVICE, or on Windows
 * and macOS the provisioned NativeTestEnvironment.DEFAULT_SERVICE_NAME - and is reported as skipped
 * where there is none (as hkdfguard-dataencryptionkey's NativeEndToEndTest). It writes no key file.
 */
class NativeEndToEndCacheTest {
    private static String service;

    @BeforeAll
    static void requireAProvisionedService() {
        service = NativeTestEnvironment.assumeService();
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
