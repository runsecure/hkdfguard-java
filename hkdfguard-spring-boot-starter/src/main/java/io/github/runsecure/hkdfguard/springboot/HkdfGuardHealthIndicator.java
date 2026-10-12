package io.github.runsecure.hkdfguard.springboot;

import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Objects;
import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;

/**
 * Reports whether the key ring's current key still works, by encrypting and decrypting a random
 * probe with it. The probe stays in memory and touches no KMS, so the check is cheap enough for
 * every health poll.
 *
 * <p>DOWN means new values can't be protected: most often the current key's provider has failed
 * closed after too many failed refreshes - its KEK was revoked or became unreachable - and has
 * zeroed the key. The {@code currentVersion} detail names the key checked; no key material, probe
 * or ciphertext is ever reported.
 */
public final class HkdfGuardHealthIndicator extends AbstractHealthIndicator {
    // Distinct from every protector and cache AAD, so a probe ciphertext could never pass as a value.
    private static final byte[] AAD = "HkdfGuard.Health".getBytes(StandardCharsets.US_ASCII);
    private static final int PROBE_LENGTH = 16;

    private final KeyRing keyRing;
    private final SecureRandom random = new SecureRandom();

    /** @param keyRing the ring whose current key to check */
    public HkdfGuardHealthIndicator(KeyRing keyRing) {
        super("The HkdfGuard key ring health check failed");
        this.keyRing = Objects.requireNonNull(keyRing, "keyRing");
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        var current = keyRing.getCurrent();
        builder.withDetail("currentVersion", current.version());

        var probe = new byte[PROBE_LENGTH];
        random.nextBytes(probe);
        var result = new byte[PROBE_LENGTH];
        // Encrypting zeroes the plaintext it is given, so it gets a copy and the probe survives to compare.
        var written = current.key().decrypt(current.key().encrypt(probe.clone(), AAD), AAD, result);

        if (written == PROBE_LENGTH && MessageDigest.isEqual(probe, result))
            builder.up();
        else
            builder.down().withDetail("error", "The current key did not decrypt what it encrypted.");
    }
}
