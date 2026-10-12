package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * Counts how many times one AES-256-GCM key has encrypted. With random 96-bit nonces, NIST SP
 * 800-38D caps a key at 2^32 encryptions; past that the chance of a repeated nonce - which breaks
 * both confidentiality and integrity for everything under the key - is no longer negligible. One
 * instance is shared by every session built on the same key (the key, not the session, is what the
 * limit applies to) - and, through {@link #forKey}, by every provider in this process that reveals
 * that key. Thread-safe.
 */
final class EncryptionBudget {
    /**
     * Hard stop: half the NIST limit, because this counter only sees its own process, and every
     * process of a deployment sharing a key file draws on the same budget. Within one process the
     * count is shared through {@link #forKey}; across processes it can't be, so the halving covers
     * two processes per key file at most.
     */
    static final long DEFAULT_LIMIT = 1L << 31;

    /** Where a telemetry warning is raised - one eighth of the limit. */
    static final long DEFAULT_WARNING_THRESHOLD = 1L << 28;

    // Budgets by key, for the life of the process: one small entry per distinct DEK revealed.
    // Indexed by an HMAC under a key generated for this process, never by the DEK or a plain hash
    // of it - a plain hash would be the same in every process and on every machine, a stable
    // fingerprint of the key sitting in memory.
    private static final byte[] REGISTRY_KEY = newRegistryKey();
    private static final ConcurrentHashMap<String, EncryptionBudget> BY_KEY = new ConcurrentHashMap<>();

    private final long warningThreshold;
    private final long limit;
    private final AtomicLong count = new AtomicLong();

    EncryptionBudget() {
        this(DEFAULT_WARNING_THRESHOLD, DEFAULT_LIMIT);
    }

    /**
     * @throws IllegalArgumentException limit is not positive, or warningThreshold is not between 1 and the limit
     */
    EncryptionBudget(long warningThreshold, long limit) {
        if (limit < 1)
            throw new IllegalArgumentException("Limit must be positive; it is " + limit + ".");
        if (warningThreshold < 1 || warningThreshold > limit)
            throw new IllegalArgumentException("Warning threshold must be between 1 and the limit; it is " + warningThreshold + ".");

        this.warningThreshold = warningThreshold;
        this.limit = limit;
    }

    /**
     * The budget for {@code key}, shared by every provider in this process that reveals the same
     * DEK - two key rings built from one key file draw on one count, not two.
     */
    static EncryptionBudget forKey(byte[] key) {
        var mac = new HMac(SHA256Digest.newInstance());
        mac.init(new KeyParameter(REGISTRY_KEY));
        mac.update(key, 0, key.length);
        var id = new byte[mac.getMacSize()];
        mac.doFinal(id, 0);
        return BY_KEY.computeIfAbsent(Hex.toHexString(id), ignored -> new EncryptionBudget());
    }

    long getWarningThreshold() {
        return warningThreshold;
    }

    long getLimit() {
        return limit;
    }

    /** Encryptions performed so far under this key. */
    long getCount() {
        return count.get();
    }

    /**
     * Reserves one encryption. Returns true exactly once, for the reservation that reaches the
     * warning threshold, so the caller can raise a single warning.
     *
     * @throws CryptographicException the limit has been reached; the key must be rotated
     */
    boolean consume() {
        var reserved = count.incrementAndGet();
        if (reserved > limit) {
            count.decrementAndGet();
            throw new CryptographicException(
                    "This key has reached its AES-GCM encryption limit of " + limit + " and must be rotated; decryption still works.");
        }

        return reserved == warningThreshold;
    }

    private static byte[] newRegistryKey() {
        var key = new byte[32];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(key);
        return key;
    }
}
