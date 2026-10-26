package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import static io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.Futures.await;
import static io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.Futures.sleep;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.CryptoProvider;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.RefreshFailurePolicy;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class AesGcmCryptoProviderFactoryImplTest {
    private static final AesGcmCryptoProviderFactoryImpl FACTORY = new AesGcmCryptoProviderFactoryImpl();

    private static byte[] wrapped() {
        return "wrapped".getBytes(StandardCharsets.UTF_8);
    }

    private static void assertRoundTrips(CryptoProvider provider) {
        var plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
        var expected = plaintext.clone();
        var encrypted = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
        var written = provider.encrypt(plaintext, encrypted);

        var decrypted = new byte[expected.length];
        assertEquals(expected.length, provider.decrypt(Arrays.copyOf(encrypted, written), decrypted));
        assertArrayEquals(expected, decrypted);
    }

    private static Integer maxRefreshFailuresOf(CryptoProvider provider) {
        return assertInstanceOf(AesGcmCryptoProviderImpl.class, provider).getMaxRefreshFailures();
    }

    @Test
    void createAsync_ProducesAWorkingProvider() {
        try (var provider = await(FACTORY.createAsync(new FakeKeyWrapper(), wrapped(), 60))) {
            assertRoundTrips(provider);
        }
    }

    @Test
    void createEphemeralAsync_CallsGenerateAndWrapExactlyOnce_AndProducesAWorkingProvider() {
        var wrapper = new FakeKeyWrapper();

        try (var provider = await(FACTORY.createEphemeralAsync(wrapper, 60))) {
            assertEquals(1, wrapper.generateAndWrapCallCount());
            assertEquals(1, wrapper.unwrapCallCount());
            assertRoundTrips(provider);
        }
    }

    @Test
    void createAndCreateEphemeral_PassTheRefreshFailurePolicyThrough() {
        try (var created = await(FACTORY.createAsync(new FakeKeyWrapper(), wrapped(), 60, 4));
             var ephemeral = await(FACTORY.createEphemeralAsync(new FakeKeyWrapper(), 60, 5));
             var defaulted = await(FACTORY.createAsync(new FakeKeyWrapper(), wrapped(), 60));
             var ephemeralDefaulted = await(FACTORY.createEphemeralAsync(new FakeKeyWrapper(), 60));
             var failOpen = await(FACTORY.createAsync(new FakeKeyWrapper(), wrapped(), 60, null))) {
            assertEquals(4, maxRefreshFailuresOf(created));
            assertEquals(5, maxRefreshFailuresOf(ephemeral));
            assertEquals(RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES, maxRefreshFailuresOf(defaulted));
            assertEquals(RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES, maxRefreshFailuresOf(ephemeralDefaulted));
            assertNull(maxRefreshFailuresOf(failOpen));
        }
    }

    @Test
    void createAndCreateEphemeral_HandTheFactorysLoggerToEveryProvider() {
        var logger = new RecordingLogger();
        var factory = new AesGcmCryptoProviderFactoryImpl(logger);
        var wrapper = new FakeKeyWrapper();

        try (var ignored1 = await(factory.createAsync(wrapper, wrapped(), 1));
             var ignored2 = await(factory.createEphemeralAsync(wrapper, 1))) {
            wrapper.throwOnUnwrap = new CryptographicException("KEK revoked");
            sleep(1400);

            // One failed refresh from each provider.
            assertTrue(logger.entries().stream().filter(e -> e.eventId() != null && e.eventId() == HkdfGuardLog.KEY_REFRESH_FAILED).count() >= 2);
        }
    }

    @Test
    void createAsync_ReturnsBeforeASlowKeyWrapperRevealsTheKey() throws InterruptedException {
        var wrapper = new AesGcmCryptoProviderImplTest.GatedKeyWrapper();

        var pending = FACTORY.createAsync(wrapper, wrapped(), 60);

        assertTrue(wrapper.unwrapStarted.await(10, TimeUnit.SECONDS));
        assertFalse(pending.isDone());

        wrapper.release();
        try (var provider = await(pending)) {
            assertRoundTrips(provider);
        }
    }

    @Test
    void createEphemeralAsync_ReturnsBeforeASlowKeyWrapperRevealsTheKey() throws InterruptedException {
        var wrapper = new AesGcmCryptoProviderImplTest.GatedKeyWrapper();

        var pending = FACTORY.createEphemeralAsync(wrapper, 60);

        assertTrue(wrapper.unwrapStarted.await(10, TimeUnit.SECONDS));
        assertFalse(pending.isDone());

        wrapper.release();
        try (var provider = await(pending)) {
            assertRoundTrips(provider);
        }
    }

    @ParameterizedTest
    @CsvSource(nullValues = "NULL", value = {"0,NULL", "301,NULL", "60,0"})
    void createAndCreateEphemeral_WithBadArguments_ThrowBeforeCallingTheKeyWrapper(int expirySeconds, Integer maxRefreshFailures) {
        var wrapper = new FakeKeyWrapper();

        assertThrows(IllegalArgumentException.class, () -> FACTORY.createAsync(wrapper, wrapped(), expirySeconds, maxRefreshFailures));
        assertThrows(IllegalArgumentException.class, () -> FACTORY.createEphemeralAsync(wrapper, expirySeconds, maxRefreshFailures));

        assertEquals(0, wrapper.unwrapCallCount());
        assertEquals(0, wrapper.generateAndWrapCallCount());
    }

    @Test
    void createAsync_WhenTheFirstRevealFails_CompletesExceptionally() {
        var wrapper = new FakeKeyWrapper();
        wrapper.throwOnUnwrap = new CryptographicException("KEK unavailable");

        assertFailsWith(CryptographicException.class, FACTORY.createAsync(wrapper, wrapped(), 60));
    }

    @Test
    void createAsync_RejectsAWrongLengthKey() {
        var wrapper = new FakeKeyWrapper();
        wrapper.unwrapBytesWrittenOverride = 16;

        var failure = assertFailsWith(CryptographicException.class, FACTORY.createAsync(wrapper, wrapped(), 60));
        assertTrue(failure.getMessage().contains("revealed 16 bytes"));
    }

    @Test
    void createEphemeralAsync_WhenTheWrapperReportsAnImpossibleLength_CompletesExceptionally() {
        var wrapper = new FakeKeyWrapper() {
            @Override
            public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
                return CompletableFuture.completedFuture(result.length + 1);
            }
        };

        assertFailsWith(CryptographicException.class, FACTORY.createEphemeralAsync(wrapper, 60));
        assertEquals(0, wrapper.unwrapCallCount());
    }
}
