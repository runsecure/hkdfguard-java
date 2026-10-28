package io.github.runsecure.hkdfguard.dataencryptionkey;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.abstractions.Utf8Utility;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.util.Objects;

/**
 * The default {@link DataProtector}. Package-private: only {@link KeyRingImpl#createProtector}
 * constructs one, so every instance is bound to a real key ring. The name is UTF-8-encoded once
 * into the AAD used for every encrypt/decrypt, so a value protected under one name fails to decrypt
 * under another. Encrypt resolves the ring's current key on every call, so it always protects new
 * data with the latest rotation; decrypt resolves whichever version the formatted value names, so
 * old versions stay readable.
 */
final class DataProtectorImpl implements DataProtector {
    private static final AttributeKey<String> NAME_ATTRIBUTE = AttributeKey.stringKey(AttributeNames.NAME);
    private static final AttributeKey<Long> PLAINTEXT_LENGTH = AttributeKey.longKey(AttributeNames.PLAINTEXT_LENGTH);
    private static final AttributeKey<Long> ENCRYPTED_LENGTH = AttributeKey.longKey(AttributeNames.ENCRYPTED_LENGTH);

    private final String name;
    private final KeyRingImpl keyRing;
    private final EncryptedFormatProvider formatProvider;
    private final byte[] aad;

    /**
     * @throws IllegalArgumentException name is not valid UTF-16: lenient encoding would give two
     *                                  different names (an unpaired surrogate each) the same AAD
     */
    DataProtectorImpl(String name, KeyRingImpl keyRing, EncryptedFormatProvider formatProvider) {
        this.name = name;
        this.keyRing = keyRing;
        this.formatProvider = formatProvider;
        this.aad = Utf8Utility.encodeStrict(name);
    }

    @Override
    public String encrypt(CharSequence plaintext) {
        Objects.requireNonNull(plaintext, "plaintext");
        var telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        try (var op = telemetry.startSpan(SpanNames.DataProtection.PROTECTOR_ENCRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.DataProtection.PROTECTOR_ENCRYPT,
                        Attributes.of(NAME_ATTRIBUTE, name, PLAINTEXT_LENGTH, (long) plaintext.length()));

            try {
                var current = keyRing.getCurrent();

                byte[] encrypted;
                var plaintextBytes = Utf8Utility.encode(plaintext);
                try {
                    encrypted = current.key().encrypt(plaintextBytes, aad);
                } finally {
                    ArrayUtility.zeroMemory(plaintextBytes);
                }

                return formatProvider.format(new KeyTrackingValue(current.version(), encrypted));
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    @Override
    public int decrypt(CharSequence encrypted, char[] result) {
        Objects.requireNonNull(encrypted, "encrypted");
        var telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        try (var op = telemetry.startSpan(SpanNames.DataProtection.PROTECTOR_DECRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.DataProtection.PROTECTOR_DECRYPT,
                        Attributes.of(NAME_ATTRIBUTE, name, ENCRYPTED_LENGTH, (long) encrypted.length()));

            try {
                var value = formatProvider.parse(encrypted);
                var key = keyRing.get(value.keyVersion());

                // AEAD ciphertext is always at least as long as the plaintext it encloses, so the
                // value's length is a safe upper bound for the decrypted UTF-8 byte count.
                return Utf8Utility.decodeWritten(value.value().length, bytes -> key.decrypt(value.value(), aad, bytes), result);
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
}
