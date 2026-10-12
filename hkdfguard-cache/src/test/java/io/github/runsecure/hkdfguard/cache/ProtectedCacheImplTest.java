package io.github.runsecure.hkdfguard.cache;

import static io.github.runsecure.hkdfguard.cache.TestRings.text;
import static io.github.runsecure.hkdfguard.cache.TestRings.utf8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ProtectedCache;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.MetricNames;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

class ProtectedCacheImplTest {
    private final KeyRingImpl ring = TestRings.ring();

    @AfterEach
    void closeRing() {
        ring.close();
    }

    private ProtectedCache cache() {
        return new ProtectedCacheImpl(ring);
    }

    @Test
    void addDecrypt_Bytes_RoundTrips_AndZeroesThePlaintext() {
        var cache = cache();
        var plaintext = utf8("top secret bytes");

        cache.add("item", plaintext);

        assertArrayEquals(new byte[plaintext.length], plaintext);
        var result = new byte[16];
        assertEquals(16, cache.decrypt("item", result));
        assertArrayEquals(utf8("top secret bytes"), result);
    }

    @Test
    void addDecrypt_Chars_RoundTrips_IncludingMultiByteUtf8() {
        var cache = cache();
        for (var value : new String[] {"top secret chars", "héllo wörld 日本語"}) {
            var name = "item-" + value.length();
            cache.add(name, value.toCharArray());

            var result = new char[value.length()];
            assertEquals(value, new String(result, 0, cache.decrypt(name, result)));
        }
    }

    @Test
    void add_TheSameNameTwice_Throws_WhateverTheAsciiCase_AndKeepsTheFirstValue() {
        var cache = cache();
        cache.add("Item", utf8("original"));

        assertThrows(IllegalArgumentException.class, () -> cache.add("item", utf8("second")));
        assertThrows(IllegalArgumentException.class, () -> cache.add("ITEM", "second".toCharArray()));

        var result = new byte[16];
        assertEquals("original", text(result, cache.decrypt("item", result)));
    }

    @Test
    void addOrUpdate_ReplacesThePreviousValue_WhateverTheAsciiCase() {
        var cache = cache();
        cache.add("Item-Name", utf8("first"));

        assertDoesNotThrow(() -> cache.addOrUpdate("ITEM-name", utf8("second-value")));
        cache.addOrUpdate("item-NAME", "third-value".toCharArray());

        var result = new byte[cache.findMaxDecryptedLength("item-name").orElseThrow()];
        assertEquals("third-value", text(result, cache.decrypt("item-name", result)));
    }

    @Test
    void decrypt_AnUnknownName_ReturnsZero_AndFindIsEmpty() {
        var cache = cache();

        assertEquals(0, cache.decrypt("missing", new byte[16]));
        assertEquals(0, cache.decrypt("missing", new char[16]));
        assertTrue(cache.findMaxDecryptedLength("missing").isEmpty());
    }

    @Test
    void findMaxDecryptedLength_IsASafeUpperBound() {
        var cache = cache();
        cache.add("item", utf8("some plaintext value"));

        var max = cache.findMaxDecryptedLength("item").orElseThrow();
        var result = new byte[max];
        var written = cache.decrypt("item", result);

        assertTrue(max >= written);
        assertEquals("some plaintext value", text(result, written));
    }

    @Test
    void everyOperation_WithSensitiveLoggingEnabled_StillRoundTrips() {
        TestRings.withSensitiveLogging(() -> {
            var cache = cache();
            cache.add("a", utf8("top secret"));
            cache.add("b", "top secret".toCharArray());
            cache.addOrUpdate("c", utf8("top secret"));
            cache.addOrUpdate("d", "top secret".toCharArray());

            for (var name : new String[] {"a", "b", "c", "d"}) {
                var result = new char[10];
                assertEquals("top secret", new String(result, 0, cache.decrypt(name, result)));
            }
            assertEquals(0, cache.decrypt("missing", new byte[16]));
        });
    }

    @Test
    void decrypt_IntoATooSmallBuffer_Throws() {
        var cache = cache();
        cache.add("item", utf8("top secret"));
        cache.add("chars", "top secret chars".toCharArray());

        assertThrows(IllegalArgumentException.class, () -> cache.decrypt("item", new byte[1]));
        assertThrows(IllegalArgumentException.class, () -> cache.decrypt("chars", new char[1]));
    }

    @Test
    void aNullName_IsRefusedByEveryWrite_AndThePlaintextIsStillZeroed() {
        var cache = cache();
        var bytes = utf8("value");
        var chars = "value".toCharArray();

        assertThrows(NullPointerException.class, () -> cache.add(null, bytes));
        assertThrows(NullPointerException.class, () -> cache.add(null, chars));
        assertThrows(NullPointerException.class, () -> cache.addOrUpdate(null, utf8("value")));
        assertThrows(NullPointerException.class, () -> cache.addOrUpdate(null, "value".toCharArray()));
        assertArrayEquals(new byte[5], bytes);
        assertArrayEquals(new char[5], chars);
    }

    @Test
    void anEmptyValue_IsRefusedByEveryWrite_AndNothingIsStored() {
        var cache = cache();

        assertThrows(IllegalArgumentException.class, () -> cache.add("item", new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> cache.add("item", new char[0]));
        assertThrows(IllegalArgumentException.class, () -> cache.addOrUpdate("item", new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> cache.addOrUpdate("item", new char[0]));
        assertTrue(cache.findMaxDecryptedLength("item").isEmpty());
    }

    @Test
    void concurrentAddsAndDecrypts_AcrossManyNames_AllRoundTrip() {
        var cache = cache();

        IntStream.range(0, 200).parallel().forEach(i -> cache.add("item-" + i, utf8("value-" + i)));
        IntStream.range(0, 200).parallel().forEach(i -> {
            var result = new byte[cache.findMaxDecryptedLength("item-" + i).orElseThrow()];
            assertEquals("value-" + i, text(result, cache.decrypt("item-" + i, result)));
        });
    }

    @Test
    void concurrentAdds_OfTheSameName_ExactlyOneSucceeds() {
        var cache = cache();
        var succeeded = new AtomicInteger();

        IntStream.range(0, 50).parallel().forEach(i -> {
            try {
                cache.add("shared-name", utf8("value-" + i));
                succeeded.incrementAndGet();
            } catch (IllegalArgumentException expected) {
                // every attempt but the winner
            }
        });

        assertEquals(1, succeeded.get());
    }

    @Test
    void withSensitiveLoggingEnabled_EachWriteLogsOneDebugEntryNamingTheItem() {
        TestRings.withSensitiveLogging(() -> {
            for (var kind = 0; kind < 4; kind++) {
                var recording = new RecordingLogger();
                var cache = new ProtectedCacheImpl(ring, recording);
                switch (kind) {
                    case 0 -> cache.add("item", utf8("value"));
                    case 1 -> cache.add("item", "value".toCharArray());
                    case 2 -> cache.addOrUpdate("item", utf8("value"));
                    default -> cache.addOrUpdate("item", "value".toCharArray());
                }

                var entries = recording.entries();
                assertEquals(1, entries.size());
                assertEquals(Level.DEBUG, entries.getFirst().level());
                assertEquals(HkdfGuardLog.SENSITIVE_OPERATION_LOGGED, entries.getFirst().eventId());
                assertTrue(entries.getFirst().message().contains("item"));
            }
        });
    }

    private final RecordingLogger logger = new RecordingLogger();

    @Test
    void aFailedWrite_LogsOperationFailedWithTheException() {
        var cache = new ProtectedCacheImpl(ring, logger);
        cache.add("item", utf8("first"));

        assertThrows(IllegalArgumentException.class, () -> cache.add("item", utf8("second")));
        assertThrows(IllegalArgumentException.class, () -> cache.add("item", "second".toCharArray()));
        assertThrows(IllegalArgumentException.class, () -> cache.addOrUpdate("other", new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> cache.addOrUpdate("other", new char[0]));

        var errors = logger.entries().stream().filter(e -> e.level() == Level.ERROR).toList();
        assertEquals(4, errors.size());
        errors.forEach(e -> {
            assertEquals(HkdfGuardLog.OPERATION_FAILED, e.eventId());
            assertInstanceOf(IllegalArgumentException.class, e.exception());
        });
    }

    @Test
    void writes_CountTowardTheCacheOperationsCounter_TaggedWithTheOperationAndResult() {
        var reader = InMemoryMetricReader.create();
        var sdk = OpenTelemetrySdk.builder().setMeterProvider(SdkMeterProvider.builder().registerMetricReader(reader).build()).build();
        HkdfGuardTelemetry.setOpenTelemetry(sdk);
        try {
            var cache = cache();
            cache.add("item", utf8("value"));
            assertThrows(IllegalArgumentException.class, () -> cache.add("item", utf8("value")));

            var points = reader.collectAllMetrics().stream()
                    .filter(m -> m.getName().equals(MetricNames.Cache.OPERATIONS))
                    .flatMap(m -> m.getLongSumData().getPoints().stream())
                    .toList();
            var operation = AttributeKey.stringKey(AttributeNames.OPERATION_NAME);
            var result = AttributeKey.stringKey(AttributeNames.RESULT);
            assertTrue(points.stream().anyMatch(p -> p.getValue() == 1 && SpanNames.Cache.ADD.equals(p.getAttributes().get(operation))
                    && "success".equals(p.getAttributes().get(result))));
            assertTrue(points.stream().anyMatch(p -> p.getValue() == 1 && SpanNames.Cache.ADD.equals(p.getAttributes().get(operation))
                    && "error".equals(p.getAttributes().get(result))));
        } finally {
            HkdfGuardTelemetry.setOpenTelemetry(null);
            sdk.close();
        }
    }

    @Test
    void largeValues_RoundTripAndTheCallersCharsAreZeroed() {
        // 15,000 UTF-8 bytes mixing 1-, 2- and 3-byte characters; then a 1 MiB value.
        var cache = cache();
        for (var value : new String[] {"é-秘密-".repeat(1500), "x".repeat(4096), "x".repeat(1024 * 1024)}) {
            var name = "big-" + value.length();
            var input = value.toCharArray();

            cache.addOrUpdate(name, input);

            assertArrayEquals(new char[input.length], input);
            var result = new char[cache.findMaxDecryptedLength(name).orElseThrow()];
            assertEquals(value, new String(result, 0, cache.decrypt(name, result)));
        }
    }

    @Test
    void asciiCaseVariantsShareAnEntry_NonAsciiCaseVariantsDoNot() {
        var cache = cache();
        cache.add("Café", utf8("value"));

        assertEquals(5, cache.decrypt("CAFé", new byte[16]));
        assertEquals(0, cache.decrypt("CAFÉ", new byte[16]));

        // A distinct name, so adding under it succeeds rather than reporting a duplicate.
        cache.add("CAFÉ", utf8("other"));
        var result = new byte[16];
        assertEquals("other", text(result, cache.decrypt("cafÉ", result)));
        assertEquals("value", text(result, cache.decrypt("café", result)));
    }
}
