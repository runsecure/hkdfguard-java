package io.github.runsecure.hkdfguard.dataencryptionkey;

import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.await;
import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.sleep;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.CryptoProvider;
import io.github.runsecure.hkdfguard.abstractions.CryptoProviderFactory;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.event.Level;

/**
 * Scheduled ephemeral key rotation: a ring with ephemeral keys adds a fresh one at the current
 * version + 1 every interval, keeps each superseded key for decryption until its retention runs out
 * and then retires it, and stops rotating when closed.
 */
class EphemeralKeyRotationTest {
    private static final Duration FAST = Duration.ofMillis(150);

    private static KeyRingBuilder builder(CryptoProviderFactory factory) {
        return new KeyRingBuilder()
                .withKeyWrapper(new TestKeys.FakeKeyWrapper(TestKeys.randomKey()))
                .withCryptoProviderFactory(factory)
                .withKeyRefreshInterval(60);
    }

    private static String encryptedVersion(String formatted) {
        return formatted.split("::")[1];
    }

    private static List<RecordingLogger.Entry> withEventId(RecordingLogger logger, int eventId) {
        return logger.entries().stream().filter(e -> e.eventId() != null && e.eventId() == eventId).toList();
    }

    private static Supplier<CompletableFuture<DataEncryptionKey>> creating(DataEncryptionKey key) {
        return () -> CompletableFuture.completedFuture(key);
    }

    private static final java.util.function.BooleanSupplier RUNNING = () -> false;

    // --- Builder configuration ---------------------------------------------------------------

    @Test
    void rotation_DefaultsToEveryTwentyFourHours() {
        assertEquals(Duration.ofHours(24), KeyRingBuilder.DEFAULT_EPHEMERAL_KEY_ROTATION_INTERVAL);
        assertEquals(KeyRingBuilder.DEFAULT_EPHEMERAL_KEY_ROTATION_INTERVAL, new KeyRingBuilder().getEphemeralKeyRotationInterval());
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 6, 24 * 7})
    void withEphemeralKeyRotation_AcceptsTheRange(int hours) {
        var builder = new KeyRingBuilder();

        assertSame(builder, builder.withEphemeralKeyRotation(Duration.ofHours(hours)));
        assertEquals(Duration.ofHours(hours), builder.getEphemeralKeyRotationInterval());
    }

    @Test
    void withEphemeralKeyRotation_RefusesLessThanAnHourOrMoreThanTheMaximum() {
        assertEquals(Duration.ofHours(1), KeyRingBuilder.MIN_EPHEMERAL_KEY_ROTATION_INTERVAL);
        assertThrows(IllegalArgumentException.class, () -> new KeyRingBuilder().withEphemeralKeyRotation(Duration.ofMinutes(59)));
        assertThrows(IllegalArgumentException.class, () -> new KeyRingBuilder().withEphemeralKeyRotation(Duration.ZERO));

        assertDoesNotThrow(() -> new KeyRingBuilder().withEphemeralKeyRotation(KeyRingBuilder.MAX_EPHEMERAL_KEY_ROTATION_INTERVAL));
        assertThrows(IllegalArgumentException.class, () ->
                new KeyRingBuilder().withEphemeralKeyRotation(KeyRingBuilder.MAX_EPHEMERAL_KEY_ROTATION_INTERVAL.plusMillis(1)));
    }

    @Test
    void retention_DefaultsToTwentyFourHours_AndAcceptsFromOneMinuteUp() {
        assertEquals(Duration.ofHours(24), new KeyRingBuilder().getEphemeralKeyRetention());

        var builder = new KeyRingBuilder();
        assertSame(builder, builder.withEphemeralKeyRetention(KeyRingBuilder.MIN_EPHEMERAL_KEY_RETENTION));
        assertEquals(Duration.ofMinutes(1), builder.getEphemeralKeyRetention());
        assertThrows(IllegalArgumentException.class, () -> new KeyRingBuilder().withEphemeralKeyRetention(Duration.ofSeconds(59)));
    }

    @Test
    void withoutEphemeralKeyRotation_TurnsItOff_AndALaterWithTurnsItBackOn() {
        var builder = new KeyRingBuilder();

        assertSame(builder, builder.withoutEphemeralKeyRotation());
        assertNull(builder.getEphemeralKeyRotationInterval());
        builder.withEphemeralKeyRotation(Duration.ofHours(6));
        assertEquals(Duration.ofHours(6), builder.getEphemeralKeyRotationInterval());
    }

    // --- Rotation behaviour ------------------------------------------------------------------

    @Test
    void aRingWithAnEphemeralKey_AddsAFreshCurrentVersionEachInterval_AndOldValuesStillDecrypt() {
        var logger = new RecordingLogger();
        try (var ring = await(builder(new AesGcmCryptoProviderFactoryImpl()).withEphemeralKey(1)
                .withEphemeralKeyRotationForTesting(FAST).withLogger(logger).buildAsync())) {
            var protector = ring.createProtector("rotation");
            var underV1 = protector.encrypt("written under v1");
            assertEquals(FAST, ring.getEphemeralKeyRotationInterval());

            sleep(FAST.toMillis() * 4);

            var current = ring.getCurrentVersion();
            assertTrue(current >= 3, "current version is " + current);
            assertEquals("v" + current, encryptedVersion(protector.encrypt("written under the current key")));
            assertEquals("v1", encryptedVersion(underV1));
            var result = new char[64];
            assertEquals("written under v1", new String(result, 0, protector.decrypt(underV1, result)));
            assertTrue(withEventId(logger, HkdfGuardLog.EPHEMERAL_KEY_ROTATED).stream().anyMatch(e -> e.level() == Level.INFO));
        }
    }

    @Test
    void aRingOfKeyFilesOnly_NeverRotates(@TempDir Path directory) throws Exception {
        var path = Files.write(directory.resolve("v4.bin"), TestKeys.utf8("wrapped"));
        var factory = new TestKeys.RecordingCryptoProviderFactory();
        try (var ring = await(builder(factory).withKeyFile(4, path).withEphemeralKeyRotationForTesting(FAST).buildAsync())) {
            sleep(FAST.toMillis() * 3);

            assertNull(ring.getEphemeralKeyRotationInterval());
            assertEquals(4, ring.getCurrentVersion());
            assertTrue(factory.createEphemeralExpirySecondsCalls.isEmpty());
        }
    }

    @Test
    void withRotationTurnedOff_TheStartupEphemeralKeyStaysCurrent_AndNothingIsRetired() {
        var factory = new TestKeys.RecordingCryptoProviderFactory();
        try (var ring = await(builder(factory).withEphemeralKey(1).withoutEphemeralKeyRotation()
                .withEphemeralKeyRetentionForTesting(FAST).buildAsync())) {
            sleep(FAST.toMillis() * 3);

            assertNull(ring.getEphemeralKeyRotationInterval());
            assertNull(ring.getEphemeralKeyRetention());
            assertEquals(1, ring.getCurrentVersion());
            assertEquals(1, factory.createEphemeralExpirySecondsCalls.size());
        }
    }

    @Test
    void rotatedKeys_AreCreatedWithTheRingsExpiryAndRefreshPolicy() {
        var factory = new TestKeys.RecordingCryptoProviderFactory();
        try (var ignored = await(builder(factory).withMaxRefreshFailures(7).withEphemeralKey(1)
                .withEphemeralKeyRotationForTesting(FAST).buildAsync())) {
            sleep(FAST.toMillis() * 3);

            assertTrue(factory.createEphemeralExpirySecondsCalls.size() >= 2);
            assertTrue(factory.createEphemeralExpirySecondsCalls.stream().allMatch(e -> e == 60));
            assertTrue(factory.maxRefreshFailuresCalls.stream().allMatch(m -> m == 7));
        }
    }

    @Test
    void aFailedRotation_KeepsTheCurrentKey_LogsAnError_AndTheNextIntervalSucceeds() {
        var logger = new RecordingLogger();
        var factory = new FlakyFactory(1, false);
        try (var ring = await(builder(factory).withEphemeralKey(1).withEphemeralKeyRotationForTesting(FAST).withLogger(logger).buildAsync())) {
            factory.armed.set(true);

            sleep(FAST.toMillis() * 4);

            var failures = withEventId(logger, HkdfGuardLog.EPHEMERAL_KEY_ROTATION_FAILED);
            assertEquals(1, failures.size());
            assertEquals(Level.ERROR, failures.getFirst().level());
            assertTrue(failures.getFirst().message().contains("version 1 stays current"));
            assertTrue(ring.getCurrentVersion() >= 2, "a later interval should have rotated");
        }
    }

    @Test
    void closeAndCloseAsync_StopRotation() {
        for (var async : new boolean[] {false, true}) {
            var factory = new TestKeys.RecordingCryptoProviderFactory();
            var ring = await(builder(factory).withEphemeralKey(1).withEphemeralKeyRotationForTesting(FAST).buildAsync());

            if (async)
                await(ring.closeAsync());
            else
                ring.close();
            var callsAtClose = factory.createEphemeralExpirySecondsCalls.size();
            sleep(FAST.toMillis() * 3);

            assertEquals(callsAtClose, factory.createEphemeralExpirySecondsCalls.size());
        }
    }

    @Test
    void close_WhileARotationIsWaitingOnTheKeyWrapper_StopsIt_AndDoesNotThrow() throws InterruptedException {
        var factory = new FlakyFactory(0, true);
        var ring = await(builder(factory).withEphemeralKey(1).withEphemeralKeyRotationForTesting(FAST).buildAsync());
        factory.armed.set(true);
        assertTrue(factory.hanging.await(10, TimeUnit.SECONDS));

        assertDoesNotThrow(ring::close);
    }

    // --- Retention ---------------------------------------------------------------------------

    @Test
    void aRotatingRing_RetiresSupersededEphemeralKeys_OnceTheirRetentionHasPassed() {
        var logger = new RecordingLogger();
        var factory = new TestKeys.RecordingCryptoProviderFactory();
        var retention = FAST.multipliedBy(5).dividedBy(2);
        try (var ring = await(builder(factory).withEphemeralKey(1).withEphemeralKeyRotationForTesting(FAST)
                .withEphemeralKeyRetentionForTesting(retention).withLogger(logger).buildAsync())) {
            var protector = ring.createProtector("retention");
            var underV1 = protector.encrypt("written under v1");
            assertEquals(retention, ring.getEphemeralKeyRetention());

            sleep(FAST.toMillis() * 8);

            // Version 1 was superseded long ago and is gone - from the ring and from memory.
            assertTrue(ring.find(1).isEmpty());
            assertThrows(NoSuchElementException.class, () -> protector.decrypt(underV1, new char[64]));
            assertTrue(withEventId(logger, HkdfGuardLog.EPHEMERAL_KEY_RETIRED).stream().anyMatch(e -> e.message().contains("version 1 ")));
            CryptoProvider first = factory.createdProviders.getFirst();
            assertThrows(IllegalStateException.class, () -> first.encrypt(new byte[1], new byte[64]));

            // The current key and the one just before it are still within retention.
            var current = ring.getCurrentVersion();
            assertTrue(current >= 5, "current version is " + current);
            assertTrue(ring.find(current).isPresent());
            assertTrue(ring.find(current - 1).isPresent());
            var result = new char[64];
            assertEquals("still works", new String(result, 0, protector.decrypt(protector.encrypt("still works"), result)));
        }
    }

    // --- Retention and single rotations, driven directly with a movable clock --------------------

    private static long nanosFromNow(Duration duration) {
        return System.nanoTime() + duration.toNanos();
    }

    @Test
    void retire_KeepsASupersededKey_UntilItsRetentionHasPassed_ThenClosesAndRemovesIt() throws InterruptedException {
        var logger = new RecordingLogger();
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            var superseded = new TestKeys.TrackingKey();
            ring.add(1, superseded);
            ring.configureEphemeralKeyRetention(Duration.ofHours(1), List.of(1));

            // The rotation adds 2 and first sees 1 as superseded, starting its retention clock.
            assertTrue(ring.rotateEphemeralKey(creating(new TestKeys.TrackingKey()), logger, RUNNING));
            assertTrue(ring.find(1).isPresent());

            ring.retireSupersededEphemeralKeys(nanosFromNow(Duration.ofMinutes(59)), logger, RUNNING);
            assertTrue(ring.find(1).isPresent());
            assertFalse(superseded.closed);

            ring.retireSupersededEphemeralKeys(nanosFromNow(Duration.ofMinutes(61)), logger, RUNNING);
            assertTrue(ring.find(1).isEmpty());
            assertThrows(NoSuchElementException.class, () -> ring.get(1));
            assertTrue(superseded.closed);
            assertEquals(2, ring.getCurrentVersion());
            var retired = withEventId(logger, HkdfGuardLog.EPHEMERAL_KEY_RETIRED);
            assertEquals(1, retired.size());
            assertTrue(retired.getFirst().message().contains("version 1 "));
        }
    }

    @Test
    void retire_NeverTouchesKeyFileVersions_OrTheCurrentKey() throws InterruptedException {
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            var keyFile = new TestKeys.TrackingKey();
            var ephemeral = new TestKeys.TrackingKey();
            ring.add(1, keyFile);   // a key file: not ephemeral
            ring.add(2, ephemeral);
            ring.configureEphemeralKeyRetention(Duration.ofHours(1), List.of(2));

            assertTrue(ring.rotateEphemeralKey(creating(new TestKeys.TrackingKey()), null, RUNNING));
            ring.retireSupersededEphemeralKeys(nanosFromNow(Duration.ofDays(365)), null, RUNNING);

            assertTrue(ring.find(1).isPresent());
            assertFalse(keyFile.closed);
            assertTrue(ring.find(2).isEmpty());
            assertTrue(ephemeral.closed);
            assertTrue(ring.find(3).isPresent()); // current, however old
            assertEquals(3, ring.getCurrentVersion());
        }
    }

    @Test
    void retire_WithoutRetentionConfigured_DoesNothing() throws InterruptedException {
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            ring.add(1, new TestKeys.TrackingKey());

            assertTrue(ring.rotateEphemeralKey(creating(new TestKeys.TrackingKey()), null, RUNNING));
            ring.retireSupersededEphemeralKeys(nanosFromNow(Duration.ofDays(365)), null, RUNNING);

            assertNull(ring.getEphemeralKeyRetention());
            assertTrue(ring.find(1).isPresent());
        }
    }

    @Test
    void retire_WhenClosingAKeyThrows_StillRemovesIt_AndLogsAnError() throws InterruptedException {
        var logger = new RecordingLogger();
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            ring.add(1, new TestKeys.TrackingKey(true));
            ring.configureEphemeralKeyRetention(Duration.ofMinutes(1), List.of(1));
            assertTrue(ring.rotateEphemeralKey(creating(new TestKeys.TrackingKey()), logger, RUNNING));

            ring.retireSupersededEphemeralKeys(nanosFromNow(Duration.ofMinutes(2)), logger, RUNNING);

            assertTrue(ring.find(1).isEmpty());
            var failures = withEventId(logger, HkdfGuardLog.EPHEMERAL_KEY_RETIREMENT_FAILED);
            assertEquals(1, failures.size());
            assertEquals(Level.ERROR, failures.getFirst().level());
        }
    }

    @Test
    void rotate_WhenTheNextVersionIsAlreadyTaken_Fails_AndClosesTheKeyItMade() throws InterruptedException {
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            ring.add(1, new TestKeys.TrackingKey());
            var made = new TestKeys.TrackingKey();

            var rotated = ring.rotateEphemeralKey(() -> {
                ring.add(2, new TestKeys.TrackingKey()); // someone else takes version 2 first
                return CompletableFuture.completedFuture(made);
            }, null, RUNNING);

            assertFalse(rotated);
            assertTrue(made.closed);
            assertEquals(2, ring.getCurrentVersion());
        }
    }

    @Test
    void rotate_AtVersionIntMaxValue_RefusesWithoutCreatingAKey() throws InterruptedException {
        var logger = new RecordingLogger();
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            ring.add(Integer.MAX_VALUE, new TestKeys.TrackingKey());
            var created = new AtomicBoolean();

            var rotated = ring.rotateEphemeralKey(() -> {
                created.set(true);
                return CompletableFuture.completedFuture(new TestKeys.TrackingKey());
            }, logger, RUNNING);

            assertFalse(rotated);
            assertFalse(created.get());
            assertEquals(Integer.MAX_VALUE, ring.getCurrentVersion());
            assertTrue(logger.entries().getFirst().exception().getMessage().contains("no higher version"));
            assertFalse(ring.rotateEphemeralKey(creating(new TestKeys.TrackingKey()), null, RUNNING));
        }
    }

    @Test
    void rotate_FailingDuringShutdown_Rethrows_AndStillClosesTheKeyItMade() {
        try (var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            ring.add(1, new TestKeys.TrackingKey());
            var made = new TestKeys.TrackingKey();
            var stopping = new AtomicBoolean();

            assertThrows(IllegalArgumentException.class, () -> ring.rotateEphemeralKey(() -> {
                stopping.set(true);
                ring.add(2, new TestKeys.TrackingKey()); // makes the rotation's own add fail
                return CompletableFuture.completedFuture(made);
            }, null, stopping::get));

            assertTrue(made.closed);
        }
    }

    @Test
    void rotate_RecordsASpanTaggedWithTheNewVersion() throws InterruptedException {
        try (var capture = new SpanCapture(); var ring = new KeyRingImpl(new DefaultFormatProviderImpl())) {
            ring.add(41, new TestKeys.TrackingKey());

            assertTrue(ring.rotateEphemeralKey(creating(new TestKeys.TrackingKey()), null, RUNNING));

            var rotations = capture.spans(SpanNames.DataProtection.KEY_RING_ROTATE_EPHEMERAL);
            assertEquals(1, rotations.size());
            assertEquals(42L, rotations.getFirst().getAttributes().get(AttributeKey.longKey(AttributeNames.KEY_VERSION)));
        }
    }

    // Creates real providers, but once armed can fail a set number of times or hang until interrupted.
    private static final class FlakyFactory implements CryptoProviderFactory {
        private final AesGcmCryptoProviderFactoryImpl inner = new AesGcmCryptoProviderFactoryImpl();
        private final AtomicInteger failures = new AtomicInteger();
        private final int failuresBeforeSuccess;
        private final boolean hang;
        final AtomicBoolean armed = new AtomicBoolean();
        final CountDownLatch hanging = new CountDownLatch(1);

        FlakyFactory(int failuresBeforeSuccess, boolean hang) {
            this.failuresBeforeSuccess = failuresBeforeSuccess;
            this.hang = hang;
        }

        @Override
        public CompletableFuture<CryptoProvider> createAsync(KeyWrapper wrapper, byte[] wrapped, int expirySeconds, Integer maxRefreshFailures) {
            return inner.createAsync(wrapper, wrapped, expirySeconds, maxRefreshFailures);
        }

        @Override
        public CompletableFuture<CryptoProvider> createEphemeralAsync(KeyWrapper wrapper, int expirySeconds, Integer maxRefreshFailures) {
            if (armed.get() && hang) {
                hanging.countDown();
                return new CompletableFuture<>(); // never completes: the ring must stop waiting on close
            }

            if (armed.get() && failures.incrementAndGet() <= failuresBeforeSuccess)
                return CompletableFuture.failedFuture(new CryptographicException("KEK unavailable"));

            return inner.createEphemeralAsync(wrapper, expirySeconds, maxRefreshFailures);
        }
    }
}
