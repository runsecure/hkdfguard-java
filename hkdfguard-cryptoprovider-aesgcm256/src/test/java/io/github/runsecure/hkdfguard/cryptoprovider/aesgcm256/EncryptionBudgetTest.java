package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class EncryptionBudgetTest {
    @Test
    void defaults_AreHalfAndOneEighthOfTheNistLimit() {
        var budget = new EncryptionBudget();

        assertEquals(1L << 31, budget.getLimit());
        assertEquals(1L << 28, budget.getWarningThreshold());
        assertEquals(0, budget.getCount());
    }

    @Test
    void consume_ReturnsTrueExactlyOnce_WhenTheWarningThresholdIsReached() {
        var budget = new EncryptionBudget(3, 10);

        var warnings = new boolean[6];
        for (var i = 0; i < warnings.length; i++)
            warnings[i] = budget.consume();

        assertArrayEquals(new boolean[] {false, false, true, false, false, false}, warnings);
        assertEquals(6, budget.getCount());
    }

    @Test
    void consume_PastTheLimit_ThrowsAndLeavesTheCountAtTheLimit() {
        var budget = new EncryptionBudget(1, 2);
        budget.consume();
        budget.consume();

        var exception = assertThrows(CryptographicException.class, budget::consume);

        assertTrue(exception.getMessage().contains("limit of 2"));
        assertEquals(2, budget.getCount());
        assertThrows(CryptographicException.class, budget::consume);
    }

    @Test
    void consume_UnderConcurrency_NeverExceedsTheLimit() throws InterruptedException {
        var budget = new EncryptionBudget(1, 1000);
        var successes = new AtomicInteger();
        var start = new CountDownLatch(1);
        var threads = new ArrayList<Thread>();

        for (var t = 0; t < 8; t++) {
            threads.add(Thread.ofPlatform().start(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    return;
                }
                for (var i = 0; i < 500; i++) {
                    try {
                        budget.consume();
                        successes.incrementAndGet();
                    } catch (CryptographicException ignored) {
                        // over the limit
                    }
                }
            }));
        }
        start.countDown();
        for (var thread : threads)
            thread.join();

        assertEquals(1000, successes.get());
        assertEquals(1000, budget.getCount());
    }

    @ParameterizedTest
    @CsvSource({"0,10", "11,10", "1,0"})
    void constructor_WithAnInvalidThresholdOrLimit_Throws(long warningThreshold, long limit) {
        assertThrows(IllegalArgumentException.class, () -> new EncryptionBudget(warningThreshold, limit));
    }

    @Test
    void theRegistry_IsKeyedByTheKeysValue_NotItsIdentity() {
        var key = FakeKeyWrapper.randomKey();

        assertSame(EncryptionBudget.forKey(key), EncryptionBudget.forKey(key.clone()));
        assertNotSame(EncryptionBudget.forKey(key), EncryptionBudget.forKey(FakeKeyWrapper.randomKey()));
    }
}
