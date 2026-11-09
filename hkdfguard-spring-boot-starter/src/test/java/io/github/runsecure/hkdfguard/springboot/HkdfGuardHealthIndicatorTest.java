package io.github.runsecure.hkdfguard.springboot;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.EncryptionLimitReachedException;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.VersionedKey;
import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Status;

/** How often the health probe spends an encryption: the key's AES-GCM budget is finite. */
class HkdfGuardHealthIndicatorTest {
    private static final long INTERVAL = HkdfGuardHealthIndicator.PROBE_REENCRYPT_INTERVAL.toNanos();

    /** A key that counts its operations; its "ciphertext" is the plaintext reversed, so it round-trips. */
    private static class CountingKey implements DataEncryptionKey {
        final AtomicInteger encryptions = new AtomicInteger();
        final AtomicInteger decryptions = new AtomicInteger();
        volatile RuntimeException encryptFailure;
        volatile RuntimeException decryptFailure;

        @Override
        public byte[] encrypt(byte[] plaintext) {
            return encrypt(plaintext, new byte[0]);
        }

        @Override
        public byte[] encrypt(byte[] plaintext, byte[] aad) {
            try {
                if (encryptFailure != null)
                    throw encryptFailure;
                encryptions.incrementAndGet();
                var ciphertext = new byte[plaintext.length];
                for (int i = 0; i < plaintext.length; i++)
                    ciphertext[i] = plaintext[plaintext.length - 1 - i];
                return ciphertext;
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] result) {
            return decrypt(ciphertext, new byte[0], result);
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
            if (decryptFailure != null)
                throw decryptFailure;
            decryptions.incrementAndGet();
            for (int i = 0; i < ciphertext.length; i++)
                result[i] = ciphertext[ciphertext.length - 1 - i];
            return ciphertext.length;
        }
    }

    /** A ring whose current key a test can replace, as a rotation would. */
    private static final class SwitchableRing implements KeyRing {
        volatile VersionedKey current;

        SwitchableRing(int version, DataEncryptionKey key) {
            current = new VersionedKey(version, key);
        }

        @Override
        public int getCurrentVersion() {
            return current.version();
        }

        @Override
        public VersionedKey getCurrent() {
            return current;
        }

        @Override
        public DataEncryptionKey get(int version) {
            return find(version).orElseThrow(NoSuchElementException::new);
        }

        @Override
        public Optional<DataEncryptionKey> find(int version) {
            var key = current;
            return key.version() == version ? Optional.of(key.key()) : Optional.empty();
        }
    }

    private final AtomicLong clock = new AtomicLong(1_000_000_000L);
    private final CountingKey key = new CountingKey();
    private final SwitchableRing ring = new SwitchableRing(3, key);
    private final HkdfGuardHealthIndicator indicator = new HkdfGuardHealthIndicator(ring, clock::get);

    @Test
    void manyPollsWithinTheInterval_EncryptOnce_AndEachDecrypts() {
        for (int i = 0; i < 1_000; i++)
            assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);

        assertThat(key.encryptions).hasValue(1);
        assertThat(key.decryptions).hasValue(1_000);
    }

    @Test
    void aPollAfterTheInterval_EncryptsAFreshProbe() {
        indicator.health();
        clock.addAndGet(INTERVAL - 1);
        indicator.health();
        assertThat(key.encryptions).hasValue(1);

        clock.addAndGet(1);
        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
        assertThat(key.encryptions).hasValue(2);
    }

    @Test
    void anotherCurrentKey_IsProbedAtOnce() {
        indicator.health();
        var rotated = new CountingKey();
        ring.current = new VersionedKey(4, rotated);

        var health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("currentVersion", 4);
        assertThat(rotated.encryptions).hasValue(1);
        assertThat(rotated.decryptions).hasValue(1);
    }

    @Test
    void aKeyThatFailsClosedBetweenProbes_IsDownOnTheNextPoll() {
        indicator.health();
        key.decryptFailure = new IllegalStateException("The key has failed closed.");

        var health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(String.valueOf(health.getDetails().get("error"))).contains("The key has failed closed.");
        assertThat(key.encryptions).hasValue(1);
    }

    @Test
    void aKeyThatStopsEncrypting_IsDownWithinOneInterval() {
        indicator.health();
        key.encryptFailure = new EncryptionLimitReachedException("The key file is past its age.");
        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);

        clock.addAndGet(INTERVAL);
        var health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(String.valueOf(health.getDetails().get("error"))).contains("past its age");
    }

    @Test
    void aFailedEncrypt_IsRetriedOnTheNextPoll_NotCached() {
        key.encryptFailure = new IllegalStateException("Suspended.");
        assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);

        key.encryptFailure = null;

        assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
        assertThat(key.encryptions).hasValue(1);
    }
}
