package io.github.runsecure.hkdfguard.dataencryptionkey;

import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.await;
import static io.github.runsecure.hkdfguard.dataencryptionkey.TestKeys.utf8;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class KeyRingImplTest {
    private static KeyRingImpl ring() {
        return new KeyRingImpl(new DefaultFormatProviderImpl());
    }

    @Test
    void currentVersion_BeforeAnyAdd_ThrowsIllegalState() {
        try (var ring = ring()) {
            assertThrows(IllegalStateException.class, ring::getCurrentVersion);
            assertThrows(IllegalStateException.class, ring::getCurrent);
        }
    }

    @Test
    void theHighestVersionAdded_IsCurrent_WhateverTheOrder() {
        try (var ring = ring()) {
            ring.add(1, TestKeys.newKey());
            assertEquals(1, ring.getCurrentVersion());
            ring.add(5, TestKeys.newKey());
            assertEquals(5, ring.getCurrentVersion());
            ring.add(3, TestKeys.newKey());
            assertEquals(5, ring.getCurrentVersion());
        }
    }

    @Test
    void add_WithSensitiveLoggingEnabled_StillWorks() {
        TestKeys.withSensitiveLogging(() -> {
            try (var ring = ring()) {
                ring.add(1, TestKeys.newKey());
                assertEquals(1, ring.getCurrentVersion());
            }
        });
    }

    @Test
    void add_ADuplicateVersion_Throws_AndLeavesOwnershipWithTheCaller() {
        var ring = ring();
        ring.add(1, TestKeys.newKey());
        var rejected = TestKeys.newKey();

        assertThrows(IllegalArgumentException.class, () -> ring.add(1, rejected));
        ring.close();

        assertTrue(rejected.encrypt(utf8("value")).length > 0);
        rejected.close();
    }

    @Test
    void getAndFind_ReturnTheRegisteredKey_OrReportAMiss() {
        try (var ring = ring()) {
            var key = TestKeys.newKey();
            ring.add(3, key);

            assertSame(key, ring.get(3));
            assertSame(key, ring.find(3).orElseThrow());
            assertTrue(ring.find(999).isEmpty());
            assertThrows(NoSuchElementException.class, () -> ring.get(999));

            var current = ring.getCurrent();
            assertEquals(3, current.version());
            assertSame(key, current.key());
        }
    }

    @Test
    void createProtector_UsesTheRingsFormatProvider() {
        var recording = new RecordingFormatProvider();
        try (var ring = new KeyRingImpl(recording)) {
            ring.add(1, TestKeys.newKey());

            var formatted = ring.createProtector("purpose").encrypt("hello");
            assertTrue(recording.formatCalled);

            var result = new char[16];
            assertEquals("hello", new String(result, 0, ring.createProtector("purpose").decrypt(formatted, result)));
            assertTrue(recording.parseCalled);
        }
    }

    @Test
    void close_ClosesEveryClosableKey_AndLeavesOthersAlone() {
        var ring = ring();
        var first = TestKeys.newKey();
        var tracking = new TestKeys.TrackingKey();
        ring.add(1, first);
        ring.add(2, tracking);
        ring.add(3, new TestKeys.NonClosableKey());

        ring.close();

        assertThrows(IllegalStateException.class, () -> first.encrypt(utf8("value")));
        assertTrue(tracking.closed);
    }

    @Test
    void close_KeepsGoingWhenAKeyFailsToClose() {
        var ring = ring();
        var failing = new TestKeys.TrackingKey(true);
        var after = new TestKeys.TrackingKey();
        ring.add(1, failing);
        ring.add(2, after);

        assertDoesNotThrow(ring::close);
        assertTrue(after.closed);
    }

    @Test
    void closeAsync_ClosesEveryKey_AndCloseTwiceIsSafe() {
        var ring = ring();
        var key = TestKeys.newKey();
        ring.add(1, key);

        await(ring.closeAsync());
        await(ring.closeAsync());
        ring.close();

        assertThrows(IllegalStateException.class, () -> key.encrypt(utf8("value")));
        var late = TestKeys.newKey();
        assertThrows(IllegalStateException.class, () -> ring.add(2, late));
        late.close();
    }

    @ParameterizedTest
    @ValueSource(ints = {Integer.MIN_VALUE, -1, 0, Integer.MAX_VALUE})
    void anyIntVersion_BecomesCurrent_AndEncryptsAndDecrypts(int version) {
        try (var ring = ring()) {
            ring.add(version, TestKeys.newKey());

            assertEquals(version, ring.getCurrentVersion());
            assertEquals(version, ring.getCurrent().version());
            var protector = ring.createProtector("range");
            var formatted = protector.encrypt("value");
            var result = new char[protector.getMaxDecryptedLength(formatted)];
            assertEquals("value", new String(result, 0, protector.decrypt(formatted, result)));
        }
    }

    @Test
    void minValue_IsReplacedByAnyHigherVersion_AndNeverReplacesOne() {
        try (var ring = ring(); var other = ring()) {
            ring.add(Integer.MIN_VALUE, TestKeys.newKey());
            ring.add(5, TestKeys.newKey());
            assertEquals(5, ring.getCurrentVersion());

            other.add(5, TestKeys.newKey());
            other.add(Integer.MIN_VALUE, TestKeys.newKey());
            assertEquals(5, other.getCurrentVersion());
        }
    }

    /** A real format provider that records being used. */
    static final class RecordingFormatProvider implements EncryptedFormatProvider {
        private final DefaultFormatProviderImpl inner = new DefaultFormatProviderImpl();
        volatile boolean formatCalled;
        volatile boolean parseCalled;

        @Override
        public String format(KeyTrackingValue value) {
            formatCalled = true;
            return inner.format(value);
        }

        @Override
        public KeyTrackingValue parse(CharSequence encrypted) {
            parseCalled = true;
            return inner.parse(encrypted);
        }

        @Override
        public int getMaxDecryptedLength(CharSequence encrypted) {
            return inner.getMaxDecryptedLength(encrypted);
        }
    }
}
