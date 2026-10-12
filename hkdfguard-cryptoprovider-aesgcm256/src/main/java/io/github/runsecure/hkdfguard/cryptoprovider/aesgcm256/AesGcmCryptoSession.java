package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.EventNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;

/**
 * An AES-256-GCM cipher bound to a single 32-byte key, supplied once at construction. Meant to be
 * held for a while - by {@link AesGcmCryptoProviderImpl} until its next background refresh, or by
 * {@link AesGcmPipelineDataProtectorImpl} for its whole lifetime - and closed (releasing every
 * cipher instance and zeroing the key) once no longer needed, rather than rebuilt per operation.
 * <p>
 * Thread-safe. A BouncyCastle GCM cipher is not: each instance carries the nonce and buffers of the
 * operation in progress, so two threads sharing one could encrypt one plaintext under the other's
 * nonce - a nonce reuse that breaks GCM. Every encrypt/decrypt here therefore takes a cipher for
 * its exclusive use from a small per-session pool and returns it after. The pool grows to the peak
 * number of concurrent operations and no further. Each pooled cipher is keyed once, when built,
 * and every later operation re-initializes it with only a fresh nonce and AAD.
 * <p>
 * Key hygiene: the raw key is copied into BouncyCastle only for that one keying, and the copy is
 * zeroed straight after; what each cipher keeps is the expanded AES key schedule and GHASH tables.
 * On close every pooled cipher is re-keyed with an all-zero key, overwriting those tables, and the
 * session's own key array is zeroed.
 */
final class AesGcmCryptoSession implements AutoCloseable {
    static final int TAG_SIZE = 16;
    static final int NONCE_SIZE = 12;
    private static final int KEY_LENGTH = 32;

    private static final SecureRandom RANDOM = CryptoServicesRegistrar.getSecureRandom();
    private static final byte[] EMPTY = new byte[0];

    private static final AttributeKey<Long> PLAINTEXT_LENGTH = AttributeKey.longKey(AttributeNames.PLAINTEXT_LENGTH);
    private static final AttributeKey<Long> CIPHERTEXT_LENGTH = AttributeKey.longKey(AttributeNames.CIPHERTEXT_LENGTH);
    private static final AttributeKey<Long> AAD_LENGTH = AttributeKey.longKey(AttributeNames.AAD_LENGTH);
    private static final AttributeKey<Long> ENCRYPTION_COUNT = AttributeKey.longKey(AttributeNames.ENCRYPTION_COUNT);
    private static final AttributeKey<Long> ENCRYPTION_LIMIT = AttributeKey.longKey(AttributeNames.ENCRYPTION_LIMIT);

    private final byte[] key;
    private final EncryptionBudget budget;
    private final Logger logger;
    // Ciphers not currently in use by an operation. tryRent pops one (or builds one if empty),
    // returnCipher pushes it back - so a cipher is only ever touched by one thread at a time.
    private final ConcurrentLinkedDeque<GCMModeCipher> idle = new ConcurrentLinkedDeque<>();
    // Serializes building a new cipher from the key against close zeroing the key.
    private final Object gate = new Object();
    private final AtomicInteger instanceCount = new AtomicInteger();
    private volatile boolean closed;

    /**
     * @param key the 32-byte AES-256 key - ownership transfers to this instance, which zeroes it on close
     * @throws IllegalArgumentException key is empty/all-zero, or not exactly 32 bytes
     */
    AesGcmCryptoSession(byte[] key) {
        this(key, new EncryptionBudget(), null);
    }

    /**
     * @param key    see {@link #AesGcmCryptoSession(byte[])}
     * @param budget the encryption count for this key - shared across every session built on the
     *               same key, since the nonce-reuse limit applies to the key, not the session
     * @param logger receives a warning when the budget's warning threshold is crossed; may be null
     */
    AesGcmCryptoSession(byte[] key, EncryptionBudget budget, Logger logger) {
        if (ArrayUtility.isNullOrEmpty(key))
            throw new IllegalArgumentException("AES key must not be empty or all zero.");
        if (key.length != KEY_LENGTH)
            throw new IllegalArgumentException("AES key must be exactly " + KEY_LENGTH + " bytes.");

        this.key = key;
        this.budget = Objects.requireNonNull(budget, "budget");
        this.logger = logger;

        // Build the first cipher eagerly so a bad key fails here, and the first operation never
        // takes the construction lock.
        idle.push(newCipher(key));
        instanceCount.set(1);
    }

    /** The key array, for tests to check it is zeroed. */
    byte[] key() {
        return key;
    }

    /** The encryption count this session draws on - the same one every session on this key shares. */
    EncryptionBudget budget() {
        return budget;
    }

    /** How many ciphers this session has built so far - the peak concurrency it has seen. */
    int instanceCount() {
        return instanceCount.get();
    }

    /** How many ciphers are pooled and not in use by an operation right now. */
    int idleInstanceCount() {
        return idle.size();
    }

    int encrypt(byte[] plaintext, byte[] result) {
        return encrypt(plaintext, EMPTY, result);
    }

    int encrypt(byte[] plaintext, byte[] aad, byte[] result) {
        var written = tryEncrypt(plaintext, aad, result);
        if (written >= 0)
            return written;

        ArrayUtility.zeroMemory(plaintext);
        throw closedException();
    }

    /**
     * Encrypts, unless this session has been closed - then returns -1 having touched nothing: no
     * encryption counted, and {@code plaintext} still intact, so a caller holding a session that
     * was retired under it can retry on the current one. Once it starts, it zeroes plaintext on
     * success and on every failure, as encrypt does.
     *
     * @return the number of bytes written, or -1 if this session is closed
     */
    int tryEncrypt(byte[] plaintext, byte[] aad, byte[] result) {
        Objects.requireNonNull(plaintext, "plaintext");
        var associatedData = aad == null ? EMPTY : aad;

        var cipher = tryRent();
        if (cipher == null)
            return -1;

        var telemetry = HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256;
        try (var op = telemetry.startSpan(SpanNames.CryptoProviderAesGcm256.ENCRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.CryptoProviderAesGcm256.ENCRYPT,
                        Attributes.of(PLAINTEXT_LENGTH, (long) plaintext.length, AAD_LENGTH, (long) associatedData.length));

            try {
                if (budget.consume()) {
                    op.span().addEvent(EventNames.ENCRYPTION_BUDGET_WARNING,
                            Attributes.of(ENCRYPTION_COUNT, budget.getCount(), ENCRYPTION_LIMIT, budget.getLimit()));
                    // A span event alone is lost without a tracer; the log is not.
                    HkdfGuardLog.encryptionBudgetWarning(logger, budget.getCount(), budget.getLimit());
                }

                return coreEncrypt(cipher, plaintext, associatedData, result);
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            } finally {
                returnCipher(cipher);
                ArrayUtility.zeroMemory(plaintext);
            }
        }
    }

    private static int coreEncrypt(GCMModeCipher cipher, byte[] plaintext, byte[] aad, byte[] result) {
        Objects.requireNonNull(result, "result");
        if (result.length < NONCE_SIZE + plaintext.length + TAG_SIZE)
            throw new IllegalArgumentException("Result buffer too small.");

        // Layout: [nonce | ciphertext | tag]
        var nonce = new byte[NONCE_SIZE];
        RANDOM.nextBytes(nonce);
        System.arraycopy(nonce, 0, result, 0, NONCE_SIZE);

        try {
            cipher.init(true, new AEADParameters(null, TAG_SIZE * 8, nonce, aad));
            var written = cipher.processBytes(plaintext, 0, plaintext.length, result, NONCE_SIZE);
            written += cipher.doFinal(result, NONCE_SIZE + written);
            return NONCE_SIZE + written;
        } catch (InvalidCipherTextException | IllegalStateException e) {
            throw new CryptographicException("AES-GCM encryption failed.", e);
        }
    }

    int decrypt(byte[] ciphertext, byte[] result) {
        return decrypt(ciphertext, EMPTY, result);
    }

    int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
        var written = tryDecrypt(ciphertext, aad, result);
        if (written >= 0)
            return written;

        throw closedException();
    }

    /**
     * Decrypts, unless this session has been closed - then returns -1, having done nothing.
     *
     * @return the number of bytes written, or -1 if this session is closed
     */
    int tryDecrypt(byte[] ciphertext, byte[] aad, byte[] result) {
        Objects.requireNonNull(ciphertext, "ciphertext");
        var associatedData = aad == null ? EMPTY : aad;

        var cipher = tryRent();
        if (cipher == null)
            return -1;

        var telemetry = HkdfGuardTelemetry.CRYPTO_PROVIDER_AES_GCM256;
        try (var op = telemetry.startSpan(SpanNames.CryptoProviderAesGcm256.DECRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.CryptoProviderAesGcm256.DECRYPT,
                        Attributes.of(CIPHERTEXT_LENGTH, (long) ciphertext.length, AAD_LENGTH, (long) associatedData.length));

            try {
                return coreDecrypt(cipher, ciphertext, associatedData, result);
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            } finally {
                returnCipher(cipher);
            }
        }
    }

    private static int coreDecrypt(GCMModeCipher cipher, byte[] ciphertext, byte[] aad, byte[] result) {
        Objects.requireNonNull(result, "result");
        if (ciphertext.length < NONCE_SIZE + TAG_SIZE)
            throw new IllegalArgumentException("Ciphertext too short.");

        var resultLength = ciphertext.length - NONCE_SIZE - TAG_SIZE;
        if (result.length < resultLength)
            throw new IllegalArgumentException("Result buffer too small.");

        var nonce = Arrays.copyOfRange(ciphertext, 0, NONCE_SIZE);
        try {
            cipher.init(false, new AEADParameters(null, TAG_SIZE * 8, nonce, aad));
            // GCM writes plaintext as it goes and only checks the tag at the end, so on failure
            // the result may already hold unauthenticated bytes: zero them before throwing.
            var written = cipher.processBytes(ciphertext, NONCE_SIZE, ciphertext.length - NONCE_SIZE, result, 0);
            written += cipher.doFinal(result, written);
            return written;
        } catch (InvalidCipherTextException e) {
            ArrayUtility.zeroMemory(result, 0, resultLength);
            throw new AuthenticationTagMismatchException(e);
        } catch (IllegalStateException e) {
            ArrayUtility.zeroMemory(result, 0, resultLength);
            throw new CryptographicException("AES-GCM decryption failed.", e);
        }
    }

    /**
     * Takes a cipher for the calling operation's exclusive use: an idle one if there is one,
     * otherwise a new one built from the key. Pair with {@link #returnCipher}.
     *
     * @throws IllegalStateException this session has been closed
     */
    GCMModeCipher rent() {
        var cipher = tryRent();
        if (cipher == null)
            throw closedException();
        return cipher;
    }

    /**
     * {@link #rent} without throwing: null once this session has been closed - including when a
     * cipher an in-flight operation returned after close is still briefly in the pool, so a closed
     * session never runs another operation.
     */
    GCMModeCipher tryRent() {
        var cipher = idle.pollFirst();
        if (cipher != null) {
            if (!closed)
                return cipher;

            // Pushed back by an operation finishing after close drained the pool: release it.
            scrub(cipher);
            return null;
        }

        synchronized (gate) {
            // close drains the pool and zeroes the key under this same lock, so a closed session
            // can't hand out a cipher built from a zeroed key.
            if (closed)
                return null;

            instanceCount.incrementAndGet();
            return newCipher(key);
        }
    }

    /**
     * Gives a cipher taken by {@link #rent} back to the pool. If the session was closed in the
     * meantime the cipher is released instead of pooled.
     */
    void returnCipher(GCMModeCipher cipher) {
        idle.push(cipher);

        // close may have drained the pool before this push landed; if so, drain it again so no
        // cipher (and its key schedule) outlives the session.
        if (closed)
            drainIdle();
    }

    private void drainIdle() {
        GCMModeCipher cipher;
        while ((cipher = idle.pollFirst()) != null)
            scrub(cipher);
    }

    /**
     * Releases every pooled cipher and zeroes the key. A cipher an in-flight operation holds is
     * released when that operation returns it. Safe to call more than once.
     */
    @Override
    public void close() {
        synchronized (gate) {
            if (closed)
                return;

            closed = true;
            drainIdle();
            ArrayUtility.zeroMemory(key);
        }
    }

    boolean isClosed() {
        return closed;
    }

    private IllegalStateException closedException() {
        return new IllegalStateException("This AES-GCM session has been closed.");
    }

    private static GCMModeCipher newCipher(byte[] key) {
        var cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        // KeyParameter copies the key, and the cipher keeps a reference to that copy (to refuse a
        // repeated key/nonce pair): zero it once the key schedule has been derived from it.
        var keyParameter = new KeyParameter(key);
        try {
            cipher.init(false, new AEADParameters(keyParameter, TAG_SIZE * 8, new byte[NONCE_SIZE]));
        } finally {
            ArrayUtility.zeroMemory(keyParameter.getKey());
        }
        return cipher;
    }

    // Re-keys a cipher with an all-zero key, overwriting the AES key schedule and GHASH tables it
    // derived from the real one, before it is dropped.
    private static void scrub(GCMModeCipher cipher) {
        try {
            cipher.init(false, new AEADParameters(new KeyParameter(new byte[KEY_LENGTH]), TAG_SIZE * 8, new byte[NONCE_SIZE]));
        } catch (RuntimeException ignored) {
            // Best effort: the cipher is being discarded either way.
        }
    }
}
