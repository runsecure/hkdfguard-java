package io.github.runsecure.hkdfguard.springboot;

import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;
import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;

/**
 * Reports whether the key ring's current key still works, by decrypting a random probe it
 * encrypted. The probe stays in memory and touches no KMS, so the check is cheap enough for every
 * health poll.
 *
 * <p>Each encryption counts against the key's AES-GCM encryption limit, and a health endpoint may
 * be polled often - by anyone, when it is exposed without authentication. So a fresh probe is
 * encrypted at most once per {@link #PROBE_REENCRYPT_INTERVAL} for each current key, and every
 * other poll only decrypts the last one. A key that has failed closed fails that decrypt at once;
 * a key that can no longer encrypt (past its key file's age, or its encryption limit) is reported
 * within one interval.
 *
 * <p>DOWN means new values can't be protected: most often the current key's provider has failed
 * closed after too many failed refreshes - its KEK was revoked or became unreachable - and has
 * zeroed the key. The {@code currentVersion} detail names the key checked; no key material, probe
 * or ciphertext is ever reported.
 */
public final class HkdfGuardHealthIndicator extends AbstractHealthIndicator {
    /** The longest a probe is reused before the current key encrypts a fresh one. */
    public static final Duration PROBE_REENCRYPT_INTERVAL = Duration.ofMinutes(1);

    // Distinct from every protector and cache AAD, so a probe ciphertext could never pass as a value.
    private static final byte[] AAD = "HkdfGuard.Health".getBytes(StandardCharsets.US_ASCII);
    private static final int PROBE_LENGTH = 16;

    /** A probe the key encrypted: random, not secret, and only ever decrypted by the same key. */
    private record Probe(DataEncryptionKey key, byte[] plaintext, byte[] ciphertext, long encryptedAt) {
        // By the arrays' contents, not their identity.
        @Override
        public boolean equals(Object other) {
            return other instanceof Probe that && key == that.key && encryptedAt == that.encryptedAt
                    && Arrays.equals(plaintext, that.plaintext) && Arrays.equals(ciphertext, that.ciphertext);
        }

        @Override
        public int hashCode() {
            return 31 * (31 * (31 * System.identityHashCode(key) + Arrays.hashCode(plaintext)) + Arrays.hashCode(ciphertext))
                    + Long.hashCode(encryptedAt);
        }

        // Lengths only: nothing a probe holds belongs in a log.
        @Override
        public String toString() {
            return "Probe[plaintext=" + plaintext.length + " bytes, ciphertext=" + ciphertext.length + " bytes, encryptedAt=" + encryptedAt + "]";
        }
    }

    private final KeyRing keyRing;
    private final LongSupplier nanoTime;
    private final SecureRandom random = new SecureRandom();
    private final AtomicReference<Probe> last = new AtomicReference<>();

    /** @param keyRing the ring whose current key to check */
    public HkdfGuardHealthIndicator(KeyRing keyRing) {
        this(keyRing, System::nanoTime);
    }

    /** Tests: the monotonic clock the probe's age is measured with. */
    HkdfGuardHealthIndicator(KeyRing keyRing, LongSupplier nanoTime) {
        super("The HkdfGuard key ring health check failed");
        this.keyRing = Objects.requireNonNull(keyRing, "keyRing");
        this.nanoTime = Objects.requireNonNull(nanoTime, "nanoTime");
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        var current = keyRing.getCurrent();
        builder.withDetail("currentVersion", current.version());

        var key = current.key();
        var now = nanoTime.getAsLong();
        var probe = last.get();
        // A rotation makes another key current: it gets a probe of its own at once.
        if (probe == null || probe.key() != key || now - probe.encryptedAt() >= PROBE_REENCRYPT_INTERVAL.toNanos()) {
            var plaintext = new byte[PROBE_LENGTH];
            random.nextBytes(plaintext);
            // Encrypting zeroes the plaintext it is given, so it gets a copy and the probe survives to compare.
            probe = new Probe(key, plaintext, key.encrypt(plaintext.clone(), AAD), now);
            last.set(probe);
        }

        var result = new byte[PROBE_LENGTH];
        var written = key.decrypt(probe.ciphertext(), AAD, result);

        if (written == PROBE_LENGTH && MessageDigest.isEqual(probe.plaintext(), result))
            builder.up();
        else
            builder.down().withDetail("error", "The current key did not decrypt what it encrypted.");
    }
}
