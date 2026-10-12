package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import static io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.Futures.await;
import static io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.Futures.awaitFailure;
import static io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.Futures.sleep;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.RefreshFailurePolicy;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.EventNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.StatusCode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.event.Level;

class AesGcmCryptoProviderImplTest {
    private static final byte[] WRAPPED = utf8("wrapped");

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] wrapped() {
        return WRAPPED.clone();
    }

    private static AesGcmCryptoProviderImpl create(KeyWrapper wrapper, int expirySeconds) {
        return await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), expirySeconds));
    }

    private static AesGcmCryptoProviderImpl create(KeyWrapper wrapper, int expirySeconds, Integer maxRefreshFailures, RecordingLogger logger) {
        return await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), expirySeconds, maxRefreshFailures, logger));
    }

    private static List<RecordingLogger.Entry> withEventId(RecordingLogger logger, int eventId) {
        return logger.entries().stream().filter(e -> e.eventId() != null && e.eventId() == eventId).toList();
    }

    @Test
    void createAsync_BuildsInitialSessionEagerly() {
        var wrapper = new FakeKeyWrapper();

        try (var ignored = create(wrapper, 60)) {
            assertEquals(1, wrapper.unwrapCallCount());
        }
    }

    @Test
    void createAsync_WhenKeyWrapperFails_CompletesExceptionally() {
        var wrapper = new FakeKeyWrapper();
        wrapper.throwOnUnwrap = new IllegalStateException("reveal failed");

        awaitFailure(IllegalStateException.class, AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 60));
    }

    @Test
    void createAsync_WhenTheKeyWrappersFutureFails_CompletesExceptionallyWithItsCause() {
        KeyWrapper wrapper = new FakeKeyWrapper() {
            @Override
            public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
                return CompletableFuture.failedFuture(new CryptographicException("KEK unavailable"));
            }
        };

        var failure = awaitFailure(CryptographicException.class, AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 60));
        assertEquals("KEK unavailable", failure.getMessage());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 301})
    void createAsync_WithExpirySecondsOutOfRange_Throws(int expirySeconds) {
        var wrapper = new FakeKeyWrapper();

        assertThrows(IllegalArgumentException.class, () -> AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), expirySeconds));
        assertEquals(0, wrapper.unwrapCallCount());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void createAsync_WithMaxRefreshFailuresBelowOne_Throws(int maxRefreshFailures) {
        assertThrows(IllegalArgumentException.class,
                () -> AesGcmCryptoProviderImpl.createAsync(new FakeKeyWrapper(), wrapped(), 60, maxRefreshFailures));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 16, 31, 33})
    void createAsync_WhenTheKeyWrapperRevealsAWrongLengthKey_FailsRatherThanUseAPartialKey(int bytesWritten) {
        var wrapper = new FakeKeyWrapper();
        wrapper.unwrapBytesWrittenOverride = bytesWritten;

        var failure = awaitFailure(CryptographicException.class, AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 60));

        assertTrue(failure.getMessage().contains("revealed " + bytesWritten + " bytes"));
    }

    @Test
    void createAsync_ReturnsBeforeASlowKeyWrapperRevealsTheKey() throws InterruptedException {
        var wrapper = new GatedKeyWrapper();

        var pending = AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 60);

        assertTrue(wrapper.unwrapStarted.await(10, TimeUnit.SECONDS));
        assertFalse(pending.isDone());

        wrapper.release();
        try (var provider = await(pending)) {
            assertRoundTrips(provider);
        }
    }

    @Test
    void backgroundRefresh_ProactivelyRevealsTheKeyAgain() {
        var wrapper = new FakeKeyWrapper();

        try (var ignored = create(wrapper, 1)) {
            sleep(1500);

            assertEquals(2, wrapper.unwrapCallCount());
        }
    }

    @Test
    void close_ClosesTheSessionAndStopsTheBackgroundRefresh() {
        var wrapper = new FakeKeyWrapper();
        var provider = create(wrapper, 1);
        var session = provider.currentSession();

        provider.close();
        sleep(1500);

        // Only the eager first reveal - the refresh must not have run after close.
        assertEquals(1, wrapper.unwrapCallCount());
        assertTrue(session.isClosed());
        assertThrows(IllegalStateException.class, () -> provider.encrypt(new byte[] {1}, new byte[64]));
    }

    @Test
    void closeAsync_ClosesTheSessionAndStopsTheBackgroundRefresh() {
        var wrapper = new FakeKeyWrapper();
        var provider = create(wrapper, 1);

        await(provider.closeAsync());
        sleep(1500);

        assertEquals(1, wrapper.unwrapCallCount());
        assertThrows(IllegalStateException.class, () -> provider.encrypt(new byte[] {1}, new byte[64]));
    }

    @Test
    void close_CalledTwiceOrMixedWithCloseAsync_DoesNotThrow() {
        var provider = create(new FakeKeyWrapper(), 60);

        await(provider.closeAsync());
        await(provider.closeAsync());
        assertDoesNotThrow(provider::close);
    }

    @Test
    void close_WhileARefreshIsFailingBecauseOfTheShutdown_DoesNotThrow() throws InterruptedException {
        // A key wrapper that reacts to shutdown by failing with a non-cancellation exception
        // (e.g. a network client torn down mid-call) must not make close throw.
        var wrapper = new FailsOnShutdownKeyWrapper();
        var provider = create(wrapper, 1);
        assertTrue(wrapper.refreshStarted.await(10, TimeUnit.SECONDS));

        assertDoesNotThrow(provider::close);
    }

    @Test
    void closeAsync_WhileARefreshIsFailingBecauseOfTheShutdown_DoesNotFail() throws InterruptedException {
        var wrapper = new FailsOnShutdownKeyWrapper();
        var provider = create(wrapper, 1);
        assertTrue(wrapper.refreshStarted.await(10, TimeUnit.SECONDS));

        assertDoesNotThrow(() -> await(provider.closeAsync()));
    }

    @Test
    void allocationLengths_AddAndRemoveTheNonceAndTag() {
        try (var provider = create(new FakeKeyWrapper(), 60)) {
            assertEquals(10 + 12 + 16, provider.getEncryptedAllocationLength(10));
            assertEquals(10, provider.getDecryptedAllocationLength(10 + 12 + 16));
            assertEquals(0, provider.getDecryptedAllocationLength(0));
            assertEquals(0, provider.getDecryptedAllocationLength(27));
            assertEquals(0, provider.getDecryptedAllocationLength(28));
        }
    }

    @Test
    void backgroundRefresh_WhenTheKeyWrapperRevealsAWrongLengthKey_RecordsItAndKeepsTheCurrentSession() {
        try (var capture = new SpanCapture()) {
            var wrapper = new FakeKeyWrapper();
            try (var provider = create(wrapper, 1)) {
                var plaintext = utf8("still works");
                var ciphertext = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
                provider.encrypt(plaintext.clone(), ciphertext);

                wrapper.unwrapBytesWrittenOverride = 16;
                sleep(1500);

                assertTrue(wrapper.unwrapCallCount() >= 2);
                assertTrue(capture.spans(SpanNames.CryptoProviderAesGcm256.BACKGROUND_REFRESH).stream()
                        .anyMatch(s -> s.getStatus().getStatusCode() == StatusCode.ERROR
                                && s.getStatus().getDescription().contains("revealed 16 bytes")));
                var decrypted = new byte[plaintext.length];
                provider.decrypt(ciphertext, decrypted);
                assertArrayEquals(plaintext, decrypted);
            }
        }
    }

    @Test
    void backgroundRefresh_WhenTheKeyWrapperFails_RecordsItAndKeepsTheCurrentSession() {
        try (var capture = new SpanCapture()) {
            var wrapper = new FakeKeyWrapper();
            try (var provider = create(wrapper, 1)) {
                var plaintext = utf8("still works");
                var ciphertext = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
                provider.encrypt(plaintext.clone(), ciphertext);

                wrapper.throwOnUnwrap = new CryptographicException("unwrap failed");
                sleep(1500);

                assertTrue(wrapper.unwrapCallCount() >= 2);
                assertTrue(capture.spans(SpanNames.CryptoProviderAesGcm256.BACKGROUND_REFRESH).stream()
                        .anyMatch(s -> s.getStatus().getStatusCode() == StatusCode.ERROR));
                var decrypted = new byte[plaintext.length];
                provider.decrypt(ciphertext, decrypted);
                assertArrayEquals(plaintext, decrypted);
            }
        }
    }

    @Test
    void backgroundRefresh_SwapsInANewSession_AndRetiresTheOldOneOnlyOneIntervalLater() {
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        try (var provider = create(wrapper, 1)) {
            var first = provider.currentSession();

            sleep(1300); // one refresh: first is retired, not yet closed
            var second = provider.currentSession();
            assertNotSame(first, second);
            assertFalse(first.isClosed());

            sleep(1000); // the next refresh closes it
            assertTrue(first.isClosed());
            assertFalse(provider.currentSession().isClosed());
        }
    }

    @Test
    void backgroundRefresh_UnderConcurrentLoad_NeverFailsAnOperationMidSwap() throws InterruptedException {
        // A stable key, as a real wrapper gives for one wrapped payload: ciphertext produced just
        // before a swap must decrypt just after it.
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        var failures = new CopyOnWriteArrayList<Throwable>();
        try (var provider = create(wrapper, 1)) {
            var deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(2500);
            var workers = new ArrayList<Thread>();
            for (var w = 0; w < 4; w++) {
                workers.add(Thread.ofPlatform().start(() -> {
                    var plaintext = utf8("pounding on it");
                    var ciphertext = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
                    var decrypted = new byte[plaintext.length];
                    while (System.nanoTime() < deadline) {
                        try {
                            provider.encrypt(plaintext.clone(), ciphertext);
                            provider.decrypt(ciphertext, decrypted);
                        } catch (Throwable t) {
                            failures.add(t);
                            return;
                        }
                    }
                }));
            }
            for (var worker : workers)
                worker.join();
        }

        assertTrue(failures.isEmpty(), () -> failures.toString());
        assertTrue(wrapper.unwrapCallCount() >= 3);
    }

    @Test
    void close_AfterRefreshes_ClosesTheRetiredSessionAsWellAsTheCurrentOne() {
        var wrapper = new FakeKeyWrapper();
        var provider = create(wrapper, 1);

        // Two ticks: the first retires the initial session, the second closes it and retires the
        // first refresh's - leaving one current and one retiring at close.
        sleep(2500);
        assertTrue(wrapper.unwrapCallCount() >= 3);
        var current = provider.currentSession();

        assertDoesNotThrow(provider::close);
        assertTrue(current.isClosed());
        assertThrows(IllegalStateException.class, () -> provider.encrypt(new byte[] {1}, new byte[64]));
    }

    @Test
    void encrypt_PastTheKeysLimit_ThrowsWhileDecryptStillWorks() {
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        try (var provider = await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 60, new EncryptionBudget(1, 2)))) {
            var plaintext = utf8("value");
            var ciphertext = new byte[provider.getEncryptedAllocationLength(plaintext.length)];

            provider.encrypt(plaintext.clone(), ciphertext);
            provider.encrypt(plaintext.clone(), new byte[ciphertext.length]);

            var exception = assertThrows(CryptographicException.class, () -> provider.encrypt(plaintext.clone(), new byte[ciphertext.length]));
            assertTrue(exception.getMessage().contains("must be rotated"));
            assertEquals(2, provider.getEncryptionCount());

            var decrypted = new byte[plaintext.length];
            provider.decrypt(ciphertext, decrypted);
            assertArrayEquals(plaintext, decrypted);
        }
    }

    @Test
    void encryptionCount_SurvivesABackgroundRefresh_BecauseTheKeyIsTheSame() {
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        try (var provider = await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 1, new EncryptionBudget(1, 4)))) {
            provider.encrypt(utf8("one"), new byte[64]);
            provider.encrypt(utf8("two"), new byte[64]);

            sleep(1500);
            assertTrue(wrapper.unwrapCallCount() >= 2);
            provider.encrypt(utf8("three"), new byte[64]);
            provider.encrypt(utf8("four"), new byte[64]);

            assertEquals(4, provider.getEncryptionCount());
            assertThrows(CryptographicException.class, () -> provider.encrypt(utf8("five"), new byte[64]));
        }
    }

    @Test
    void encrypt_CrossingTheWarningThreshold_RaisesTheBudgetWarningEventOnce() {
        try (var capture = new SpanCapture()) {
            var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
            try (var provider = await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 60, new EncryptionBudget(2, 7919)))) {
                for (var i = 0; i < 4; i++)
                    provider.encrypt(utf8("value"), new byte[64]);
            }

            var warnings = capture.spans(SpanNames.CryptoProviderAesGcm256.ENCRYPT).stream()
                    .flatMap(s -> s.getEvents().stream())
                    .filter(e -> e.getName().equals(EventNames.ENCRYPTION_BUDGET_WARNING))
                    .toList();
            assertEquals(1, warnings.size());
            assertEquals(2L, warnings.getFirst().getAttributes().get(AttributeKey.longKey(AttributeNames.ENCRYPTION_COUNT)));
            assertEquals(7919L, warnings.getFirst().getAttributes().get(AttributeKey.longKey(AttributeNames.ENCRYPTION_LIMIT)));
        }
    }

    @Test
    void crossingTheWarningThreshold_IsAlsoLogged_SoItIsSeenWithoutATracer() {
        var logger = new RecordingLogger();
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        try (var provider = await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 60, null, new EncryptionBudget(2, 10), logger))) {
            for (var i = 0; i < 4; i++)
                provider.encrypt(utf8("value"), new byte[64]);
        }

        var warnings = withEventId(logger, HkdfGuardLog.ENCRYPTION_BUDGET_WARNING);
        assertEquals(1, warnings.size());
        assertEquals(Level.WARN, warnings.getFirst().level());
        assertTrue(warnings.getFirst().message().contains("2 encryptions of its 10"));
    }

    @Test
    void publicLimits_MatchTheBudgetDefaults() {
        assertEquals(1L << 31, AesGcmCryptoProviderImpl.MAX_ENCRYPTIONS_PER_KEY);
        assertEquals(1L << 28, AesGcmCryptoProviderImpl.ENCRYPTION_WARNING_THRESHOLD);
    }

    @Test
    void failClosed_IsTheDefault_AndNullOptsIntoFailOpen() {
        try (var defaulted = create(new FakeKeyWrapper(), 60);
             var failOpen = await(AesGcmCryptoProviderImpl.createAsync(new FakeKeyWrapper(), wrapped(), 60, (Integer) null))) {
            assertEquals(RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES, defaulted.getMaxRefreshFailures());
            assertNull(failOpen.getMaxRefreshFailures());
            assertFalse(defaulted.isKeyAccessSuspended());
        }
    }

    // --- One encryption budget per key, process-wide -----------------------------------------

    @Test
    void twoProvidersRevealingTheSameKey_DrawOnOneEncryptionCount() {
        var key = FakeKeyWrapper.randomKey();
        try (var first = create(new FakeKeyWrapper(key), 60);
             var second = create(new FakeKeyWrapper(key), 60);
             var other = create(new FakeKeyWrapper(FakeKeyWrapper.randomKey()), 60)) {
            first.encrypt(utf8("one"), new byte[64]);
            second.encrypt(utf8("two"), new byte[64]);
            second.encrypt(utf8("three"), new byte[64]);

            assertEquals(3, first.getEncryptionCount());
            assertEquals(3, second.getEncryptionCount());
            assertEquals(0, other.getEncryptionCount());
        }
    }

    @Test
    void theSharedCount_OutlivesAProvider_SoRebuildingFromTheSameKeyFileDoesNotResetIt() {
        var key = FakeKeyWrapper.randomKey();
        var first = create(new FakeKeyWrapper(key), 60);
        first.encrypt(utf8("one"), new byte[64]);
        await(first.closeAsync());

        try (var rebuilt = create(new FakeKeyWrapper(key), 60)) {
            assertEquals(1, rebuilt.getEncryptionCount());
        }
    }

    // --- Refresh-failure policy --------------------------------------------------------------

    @Test
    void failClosed_AfterTheConfiguredConsecutiveFailures_SuspendsOperationsUntilARefreshSucceeds() {
        try (var capture = new SpanCapture()) {
            var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
            try (var provider = await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 1, 2))) {
                var plaintext = utf8("survives");
                var ciphertext = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
                provider.encrypt(plaintext.clone(), ciphertext);

                // Two consecutive failed refreshes (ticks at ~1 s and ~2 s).
                wrapper.throwOnUnwrap = new CryptographicException("KEK unavailable");
                sleep(2600);

                assertTrue(provider.isKeyAccessSuspended());
                var encryptError = assertThrows(CryptographicException.class, () -> provider.encrypt(utf8("x"), new byte[64]));
                assertTrue(encryptError.getMessage().contains("suspended"));
                assertThrows(CryptographicException.class, () -> provider.decrypt(ciphertext, new byte[plaintext.length]));
                var suspended = capture.spans(SpanNames.CryptoProviderAesGcm256.BACKGROUND_REFRESH).stream()
                        .flatMap(s -> s.getEvents().stream())
                        .filter(e -> e.getName().equals(EventNames.KEY_ACCESS_SUSPENDED))
                        .toList();
                assertEquals(1, suspended.size());
                assertEquals(2L, suspended.getFirst().getAttributes().get(AttributeKey.longKey(AttributeNames.CONSECUTIVE_FAILURES)));

                // The KEK comes back: the next successful refresh resumes service with the same DEK.
                wrapper.throwOnUnwrap = null;
                sleep(1300);

                assertFalse(provider.isKeyAccessSuspended());
                var decrypted = new byte[plaintext.length];
                provider.decrypt(ciphertext, decrypted);
                assertArrayEquals(plaintext, decrypted);
            }
        }
    }

    @Test
    void failClosed_LogsEveryFailedRefresh_TheSuspension_AndTheResumption() {
        var logger = new RecordingLogger();
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        try (var provider = create(wrapper, 1, 2, logger)) {
            var revoked = new CryptographicException("KEK revoked");

            wrapper.throwOnUnwrap = revoked; // ticks ~1 s and ~2 s fail
            sleep(2600);

            var failures = withEventId(logger, HkdfGuardLog.KEY_REFRESH_FAILED);
            assertEquals(2, failures.size());
            for (var failure : failures) {
                assertEquals(Level.ERROR, failure.level());
                assertSame(revoked, failure.exception());
                assertTrue(failure.message().contains("fail closed after 2 consecutive failures"));
            }
            var suspended = withEventId(logger, HkdfGuardLog.KEY_ACCESS_SUSPENDED);
            assertEquals(1, suspended.size());
            assertTrue(suspended.getFirst().markers().contains(HkdfGuardLog.CRITICAL));
            assertTrue(suspended.getFirst().message().contains("after 2 consecutive failed refreshes"));
            assertTrue(withEventId(logger, HkdfGuardLog.KEY_ACCESS_RESUMED).isEmpty());

            wrapper.throwOnUnwrap = null; // tick ~3 s succeeds
            sleep(1000);

            var resumed = withEventId(logger, HkdfGuardLog.KEY_ACCESS_RESUMED);
            assertEquals(1, resumed.size());
            assertEquals(Level.INFO, resumed.getFirst().level());
            assertFalse(provider.isKeyAccessSuspended());
        }
    }

    @Test
    void failOpen_StillLogsEveryFailedRefreshAsAnError_ButNeverSuspends() {
        var logger = new RecordingLogger();
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        try (var provider = create(wrapper, 1, null, logger)) {
            wrapper.throwOnUnwrap = new CryptographicException("KEK unreachable");
            sleep(2600);

            var failures = withEventId(logger, HkdfGuardLog.KEY_REFRESH_FAILED);
            assertTrue(failures.size() >= 2);
            assertTrue(failures.stream().allMatch(e -> e.message().contains("fail open")));
            assertTrue(failures.stream().anyMatch(e -> e.message().contains("(2 consecutive)")));
            assertTrue(withEventId(logger, HkdfGuardLog.KEY_ACCESS_SUSPENDED).isEmpty());
            assertFalse(provider.isKeyAccessSuspended());

            // A success after failures under fail-open resets the count but was never a suspension.
            wrapper.throwOnUnwrap = null;
            sleep(1200);
            assertTrue(withEventId(logger, HkdfGuardLog.KEY_ACCESS_RESUMED).isEmpty());
        }
    }

    // --- Failures outside the Exception hierarchy --------------------------------------------

    @Test
    void failClosed_AnErrorFromTheKeyWrapper_CountsTowardThePolicy_AndTheLoopKeepsRunning() {
        var logger = new RecordingLogger();
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        try (var provider = create(wrapper, 1, 2, logger)) {
            var plaintext = utf8("survives");
            var ciphertext = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
            provider.encrypt(plaintext.clone(), ciphertext);

            // Thrown synchronously, as a broken native binding would: before this change it ended
            // the refresh thread, and the provider kept serving its key forever.
            var linkage = new LinkageError("native binding broke");
            wrapper.errorOnUnwrap = linkage; // ticks ~1 s and ~2 s fail
            sleep(2600);

            var failures = withEventId(logger, HkdfGuardLog.KEY_REFRESH_FAILED);
            assertEquals(2, failures.size());
            assertTrue(failures.stream().allMatch(e -> e.exception() == linkage));
            assertEquals(1, withEventId(logger, HkdfGuardLog.KEY_ACCESS_SUSPENDED).size());
            assertTrue(provider.isKeyAccessSuspended());
            assertThrows(CryptographicException.class, () -> provider.decrypt(ciphertext, new byte[plaintext.length]));

            // The loop is still alive: the next tick re-reveals the key and resumes service.
            wrapper.errorOnUnwrap = null;
            sleep(1300);

            assertEquals(1, withEventId(logger, HkdfGuardLog.KEY_ACCESS_RESUMED).size());
            assertFalse(provider.isKeyAccessSuspended());
            var decrypted = new byte[plaintext.length];
            provider.decrypt(ciphertext, decrypted);
            assertArrayEquals(plaintext, decrypted);
        }
    }

    @Test
    void failOpen_AnErrorFromTheKeyWrapper_IsLoggedEveryTick_AndNeverSuspends() {
        var logger = new RecordingLogger();
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        try (var provider = create(wrapper, 1, null, logger)) {
            wrapper.errorOnUnwrap = new OutOfMemoryError("simulated");
            sleep(2600);

            var failures = withEventId(logger, HkdfGuardLog.KEY_REFRESH_FAILED);
            assertTrue(failures.size() >= 2, "every tick should still run and log");
            assertTrue(failures.stream().allMatch(e -> e.exception() instanceof OutOfMemoryError));
            assertFalse(provider.isKeyAccessSuspended());
            assertTrue(provider.encrypt(utf8("still open"), new byte[64]) > 0);
        }
    }

    @Test
    void failClosed_ALoggerThatThrows_CannotStopTheSuspension() {
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        try (var provider = await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 1, 1, new ThrowingLogger()))) {
            wrapper.throwOnUnwrap = new CryptographicException("KEK revoked"); // tick ~1 s fails
            sleep(1300);

            assertTrue(provider.isKeyAccessSuspended());
            assertThrows(CryptographicException.class, () -> provider.encrypt(utf8("x"), new byte[64]));

            // And the loop survived the logger: the next good tick resumes service.
            wrapper.throwOnUnwrap = null;
            sleep(1000);
            assertFalse(provider.isKeyAccessSuspended());
        }
    }

    @Test
    void refreshLoopTerminated_UnderFailClosed_ZeroesTheKey_RefusesEveryOperation_AndLogsCritical() {
        var logger = new RecordingLogger();
        try (var provider = create(new FakeKeyWrapper(), 300, 3, logger)) {
            var session = provider.currentSession();
            var cause = new StackOverflowError("simulated");

            provider.onRefreshLoopTerminated(cause);

            assertTrue(session.isClosed());
            assertTrue(ArrayUtilityProbe.isZero(session.key()));
            assertTrue(provider.isKeyAccessSuspended());
            var plaintext = utf8("refused");
            var error = assertThrows(CryptographicException.class, () -> provider.encrypt(plaintext, new byte[64]));
            assertTrue(error.getMessage().contains("stopped unexpectedly"));
            assertTrue(ArrayUtilityProbe.isZero(plaintext), "the CryptoProvider contract still zeroes plaintext");

            var terminated = withEventId(logger, HkdfGuardLog.BACKGROUND_TASK_TERMINATED);
            assertEquals(1, terminated.size());
            assertEquals(Level.ERROR, terminated.getFirst().level());
            assertTrue(terminated.getFirst().markers().contains(HkdfGuardLog.CRITICAL));
            assertSame(cause, terminated.getFirst().exception());
            assertTrue(terminated.getFirst().message().contains("background key refresh"));
            assertTrue(terminated.getFirst().message().contains("suspended"));
        }
    }

    @Test
    void refreshLoopTerminated_UnderFailOpen_KeepsServing_ButLogsCritical() {
        var logger = new RecordingLogger();
        try (var provider = create(new FakeKeyWrapper(), 300, null, logger)) {
            provider.onRefreshLoopTerminated(new LinkageError("simulated"));

            assertFalse(provider.isKeyAccessSuspended());
            assertRoundTrips(provider);

            var terminated = withEventId(logger, HkdfGuardLog.BACKGROUND_TASK_TERMINATED);
            assertEquals(1, terminated.size());
            assertTrue(terminated.getFirst().markers().contains(HkdfGuardLog.CRITICAL));
            assertTrue(terminated.getFirst().message().contains("no longer be detected"));
        }
    }

    @Test
    void refreshLoopTerminated_WhileClosing_DoesNothing() {
        var logger = new RecordingLogger();
        var provider = create(new FakeKeyWrapper(), 300, 3, logger);
        provider.close();

        provider.onRefreshLoopTerminated(new LinkageError("on the way out"));

        assertTrue(withEventId(logger, HkdfGuardLog.BACKGROUND_TASK_TERMINATED).isEmpty());
        assertThrows(IllegalStateException.class, () -> provider.encrypt(utf8("x"), new byte[64]));
    }

    @Test
    void successfulRefreshes_LogNothing() {
        var logger = new RecordingLogger();
        try (var ignored = create(new FakeKeyWrapper(), 1, 1, logger)) {
            sleep(1300);

            assertTrue(logger.entries().isEmpty());
        }
    }

    @Test
    void failClosed_CountsOnlyConsecutiveFailures_ASuccessResetsTheCount() {
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        try (var provider = await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 1, 2))) {
            wrapper.throwOnUnwrap = new CryptographicException("blip"); // tick ~1 s fails
            sleep(1300);
            wrapper.throwOnUnwrap = null;                                 // tick ~2 s succeeds
            sleep(1000);
            wrapper.throwOnUnwrap = new CryptographicException("blip"); // tick ~3 s fails
            sleep(1000);

            assertTrue(wrapper.unwrapCallCount() >= 4);
            assertFalse(provider.isKeyAccessSuspended());
            assertEquals("still open".length() + 28, provider.encrypt(utf8("still open"), new byte[64]));
        }
    }

    @Test
    void close_WhileSuspended_DoesNotThrow_AndLaterUseReportsClosedNotSuspended() {
        var wrapper = new FakeKeyWrapper();
        var provider = await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 1, 1));
        wrapper.throwOnUnwrap = new CryptographicException("KEK unavailable");
        sleep(1500);
        assertTrue(provider.isKeyAccessSuspended());

        assertDoesNotThrow(provider::close);
        assertFalse(provider.isKeyAccessSuspended());
        assertThrows(IllegalStateException.class, () -> provider.encrypt(new byte[] {1}, new byte[64]));
    }

    @Test
    void failClosed_AfterASuccessfulRefresh_ClosesTheRetiredSessionToo() {
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey());
        try (var provider = await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 1, 1))) {
            var first = provider.currentSession();
            sleep(1300); // tick ~1 s succeeds: the first session is retired
            assertTrue(wrapper.unwrapCallCount() >= 2);
            var second = provider.currentSession();
            wrapper.throwOnUnwrap = new CryptographicException("KEK revoked");
            sleep(1000); // tick ~2 s fails: suspend

            assertTrue(provider.isKeyAccessSuspended());
            assertTrue(first.isClosed());
            assertTrue(second.isClosed());
            assertThrows(CryptographicException.class, () -> provider.encrypt(utf8("x"), new byte[64]));
        }
    }

    @Test
    void close_FromInsideAKeyWrapperCall_DoesNotDeadlock() throws InterruptedException {
        var holder = new AesGcmCryptoProviderImpl[1];
        var closedFromInside = new CountDownLatch(1);
        var calls = new AtomicInteger();
        KeyWrapper wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey()) {
            @Override
            public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
                if (calls.incrementAndGet() > 1) {
                    holder[0].close();
                    closedFromInside.countDown();
                }
                return super.unwrapAsync(wrapped, result);
            }
        };

        holder[0] = create(wrapper, 1);

        assertTrue(closedFromInside.await(10, TimeUnit.SECONDS));
        assertThrows(IllegalStateException.class, () -> holder[0].encrypt(new byte[] {1}, new byte[64]));
    }

    private static void assertRoundTrips(AesGcmCryptoProviderImpl provider) {
        var plaintext = utf8("top secret");
        var encrypted = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
        var written = provider.encrypt(plaintext.clone(), encrypted);

        var decrypted = new byte[plaintext.length];
        assertEquals(plaintext.length, provider.decrypt(Arrays.copyOf(encrypted, written), decrypted));
        assertArrayEquals(plaintext, decrypted);
    }

    // A key wrapper whose unwrap waits until released - standing in for a network-backed KMS - so
    // a test can observe the creating call returning before the key is revealed.
    static final class GatedKeyWrapper implements KeyWrapper {
        final CountDownLatch unwrapStarted = new CountDownLatch(1);
        private final CompletableFuture<Void> gate = new CompletableFuture<>();
        private final byte[] key = FakeKeyWrapper.randomKey();

        void release() {
            gate.complete(null);
        }

        @Override
        public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
            var wrapped = utf8("wrapped");
            System.arraycopy(wrapped, 0, result, 0, wrapped.length);
            return CompletableFuture.completedFuture(wrapped.length);
        }

        @Override
        public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
            unwrapStarted.countDown();
            return gate.thenApplyAsync(ignored -> {
                System.arraycopy(key, 0, result, 0, key.length);
                return key.length;
            });
        }
    }

    // Reveals a key once (the eager first reveal); every later unwrap blocks until the refresh
    // thread is interrupted by close, then fails with a CryptographicException rather than an
    // interruption.
    private static final class FailsOnShutdownKeyWrapper implements KeyWrapper {
        final CountDownLatch refreshStarted = new CountDownLatch(1);
        private final AtomicInteger calls = new AtomicInteger();

        @Override
        public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
            if (calls.incrementAndGet() == 1) {
                System.arraycopy(FakeKeyWrapper.randomKey(), 0, result, 0, 32);
                return CompletableFuture.completedFuture(32);
            }

            refreshStarted.countDown();
            try {
                Thread.sleep(Long.MAX_VALUE);
            } catch (InterruptedException e) {
                throw new CryptographicException("KMS connection closed during shutdown.");
            }
            return CompletableFuture.completedFuture(0);
        }
    }

    private static final class ArrayUtilityProbe {
        static boolean isZero(byte[] bytes) {
            for (var b : bytes)
                if (b != 0)
                    return false;
            return true;
        }
    }

    // A logger whose every call throws, as a misconfigured appender might.
    private static final class ThrowingLogger extends org.slf4j.helpers.LegacyAbstractLogger implements org.slf4j.spi.LoggingEventAware {
        ThrowingLogger() {
            this.name = "throwing";
        }

        @Override
        public void log(org.slf4j.event.LoggingEvent event) {
            throw new IllegalStateException("appender failed");
        }

        @Override
        protected void handleNormalizedLoggingCall(Level level, org.slf4j.Marker marker, String messagePattern, Object[] arguments, Throwable throwable) {
            throw new IllegalStateException("appender failed");
        }

        @Override
        protected String getFullyQualifiedCallerName() {
            return null;
        }

        @Override
        public boolean isTraceEnabled() {
            return true;
        }

        @Override
        public boolean isDebugEnabled() {
            return true;
        }

        @Override
        public boolean isInfoEnabled() {
            return true;
        }

        @Override
        public boolean isWarnEnabled() {
            return true;
        }

        @Override
        public boolean isErrorEnabled() {
            return true;
        }
    }
}
