package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;
import io.github.runsecure.hkdfguard.abstractions.Utf8Utility;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.nio.CharBuffer;
import java.util.Base64;
import java.util.NoSuchElementException;
import java.util.Objects;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

/**
 * AES-256-GCM {@link PipelineDataProtector}: generates a random 32-byte key in memory at
 * construction and drives a single {@link AesGcmCryptoSession} around it for its whole lifetime -
 * no key wrapper, no key ring, no refresh. Each encrypt/decrypt binds the secret identifier as AAD
 * (via {@link ProtectedConfigurationPurpose}); output is formatted via the supplied
 * {@link EncryptedFormatProvider} and tagged with {@code keyVersion}. close zeroes the key and its
 * base64 form; any use afterwards throws {@link IllegalStateException}.
 */
public final class AesGcmPipelineDataProtectorImpl implements PipelineDataProtector {
    private static final int KEY_LENGTH = 32;

    private static final AttributeKey<String> NAME = AttributeKey.stringKey(AttributeNames.NAME);
    private static final AttributeKey<Long> PLAINTEXT_LENGTH = AttributeKey.longKey(AttributeNames.PLAINTEXT_LENGTH);
    private static final AttributeKey<Long> ENCRYPTED_LENGTH = AttributeKey.longKey(AttributeNames.ENCRYPTED_LENGTH);

    private final EncryptedFormatProvider formatProvider;
    private final int keyVersion;
    private final byte[] key;
    private final EncryptionBudget budget;
    private final Object gate = new Object();
    private char[] base64;
    private volatile AesGcmCryptoSession session;

    /**
     * @param formatProvider formats/parses the protected values, e.g. DefaultFormatProviderImpl
     * @param keyVersion     the version stamped on every value - the version this key will be
     *                       registered under once wrapped
     */
    public AesGcmPipelineDataProtectorImpl(EncryptedFormatProvider formatProvider, int keyVersion) {
        this(formatProvider, keyVersion, newKey());
    }

    /** @param key the 32-byte key - ownership transfers to this instance, which zeroes it on close */
    AesGcmPipelineDataProtectorImpl(EncryptedFormatProvider formatProvider, int keyVersion, byte[] key) {
        this(formatProvider, keyVersion, key, new EncryptionBudget());
    }

    AesGcmPipelineDataProtectorImpl(EncryptedFormatProvider formatProvider, int keyVersion, byte[] key, EncryptionBudget budget) {
        this.formatProvider = Objects.requireNonNull(formatProvider, "formatProvider");
        this.keyVersion = keyVersion;
        this.session = new AesGcmCryptoSession(key, budget, null);
        this.key = key;
        this.budget = budget;
    }

    private static byte[] newKey() {
        var key = new byte[KEY_LENGTH];
        CryptoServicesRegistrar.getSecureRandom().nextBytes(key);
        return key;
    }

    /** The key array, for tests to check it is zeroed. */
    byte[] key() {
        return key;
    }

    /** The base64 key buffer once getKeyAsBase64 has run, for tests to check it is zeroed. */
    char[] base64Buffer() {
        synchronized (gate) {
            return base64;
        }
    }

    @Override
    public int getKeyVersion() {
        return keyVersion;
    }

    /** Encryptions performed under this key so far - see {@link AesGcmCryptoProviderImpl#MAX_ENCRYPTIONS_PER_KEY}. */
    public long getEncryptionCount() {
        return budget.getCount();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Encoded once; every call returns a read-only view of the same buffer.
     *
     * @throws IllegalStateException this instance has been closed
     */
    @Override
    public CharBuffer getKeyAsBase64() {
        synchronized (gate) {
            session();

            if (base64 == null) {
                // The key in text form, held until close.
                var encoded = Base64.getEncoder().encode(key);
                try {
                    var chars = new char[encoded.length];
                    for (var i = 0; i < encoded.length; i++)
                        chars[i] = (char) encoded[i];
                    base64 = chars;
                } finally {
                    ArrayUtility.zeroMemory(encoded);
                }
            }

            return CharBuffer.wrap(base64).asReadOnlyBuffer();
        }
    }

    @Override
    public String encrypt(CharSequence plaintext, CharSequence secretIdentifier) {
        Objects.requireNonNull(plaintext, "plaintext");
        var telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        try (var op = telemetry.startSpan(SpanNames.DataProtection.PROTECTOR_ENCRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.DataProtection.PROTECTOR_ENCRYPT,
                        Attributes.of(NAME, String.valueOf(secretIdentifier), PLAINTEXT_LENGTH, (long) plaintext.length()));

            try {
                var current = session();
                var aad = ProtectedConfigurationPurpose.aadFor(secretIdentifier);
                var plaintextBytes = Utf8Utility.encode(plaintext);
                try {
                    var ciphertext = new byte[AesGcmCryptoSession.NONCE_SIZE + plaintextBytes.length + AesGcmCryptoSession.TAG_SIZE];
                    current.encrypt(plaintextBytes, aad, ciphertext);
                    return formatProvider.format(new KeyTrackingValue(keyVersion, ciphertext));
                } finally {
                    ArrayUtility.zeroMemory(plaintextBytes);
                }
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws NoSuchElementException the value was protected under a different key version
     */
    @Override
    public int decrypt(CharSequence encrypted, CharSequence secretIdentifier, char[] result) {
        Objects.requireNonNull(encrypted, "encrypted");
        var telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        try (var op = telemetry.startSpan(SpanNames.DataProtection.PROTECTOR_DECRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.DataProtection.PROTECTOR_DECRYPT,
                        Attributes.of(NAME, String.valueOf(secretIdentifier), ENCRYPTED_LENGTH, (long) encrypted.length()));

            try {
                var current = session();
                var aad = ProtectedConfigurationPurpose.aadFor(secretIdentifier);
                var value = formatProvider.parse(encrypted);
                if (value.keyVersion() != keyVersion)
                    throw new NoSuchElementException("No key is registered for version " + value.keyVersion() + ".");

                // AEAD ciphertext is always longer than the plaintext it encloses.
                var plaintextBytes = new byte[value.value().length];
                try {
                    var bytesWritten = current.decrypt(value.value(), aad, plaintextBytes);
                    return Utf8Utility.decode(plaintextBytes, bytesWritten, result);
                } finally {
                    ArrayUtility.zeroMemory(plaintextBytes);
                }
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    @Override
    public int getMaxDecryptedLength(CharSequence encrypted) {
        return formatProvider.getMaxDecryptedLength(encrypted);
    }

    private AesGcmCryptoSession session() {
        var current = session;
        if (current == null)
            throw new IllegalStateException("This pipeline data protector has been closed.");
        return current;
    }

    /** Closes the session, zeroing the key, and zeroes its base64 form. Safe to call more than once. */
    @Override
    public void close() {
        synchronized (gate) {
            var current = session;
            if (current == null)
                return;

            session = null;
            current.close();
            ArrayUtility.zeroMemory(base64);
        }
    }
}
