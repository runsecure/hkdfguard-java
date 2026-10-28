package io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider;

import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.dataencryptionkey.utilities.Base64ConversionUtility;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.util.Objects;

/**
 * The {@code enc::v{version}::{base64}} wire format, identical on every port. Formatted values are
 * capped at {@link #getMaxEncryptedLength()} characters (4096 by default, which leaves room for
 * about 3 KB of UTF-8 plaintext): parse rejects anything longer before decoding it, so oversized
 * input can't force a large allocation ahead of any cryptographic check, and format refuses to
 * produce a value parse would then reject.
 */
public class DefaultFormatProviderImpl implements EncryptedFormatProvider {
    public static final int DEFAULT_MAX_ENCRYPTED_LENGTH = 4096;

    private static final String ENC_PREFIX = "enc";
    private static final String DELIMITER = "::";
    private static final String VERSION_PREFIX = "v";
    private static final String MALFORMED = "Invalid encrypted format. Expected '" + ENC_PREFIX + DELIMITER + VERSION_PREFIX + "<version>" + DELIMITER + "<base64>'.";

    private static final AttributeKey<Long> KEY_VERSION = AttributeKey.longKey(AttributeNames.KEY_VERSION);
    private static final AttributeKey<Long> VALUE_LENGTH = AttributeKey.longKey(AttributeNames.VALUE_LENGTH);
    private static final AttributeKey<Long> ENCRYPTED_LENGTH = AttributeKey.longKey(AttributeNames.ENCRYPTED_LENGTH);

    private final int maxEncryptedLength;

    /** A provider with the default {@link #DEFAULT_MAX_ENCRYPTED_LENGTH} limit. */
    public DefaultFormatProviderImpl() {
        this(DEFAULT_MAX_ENCRYPTED_LENGTH);
    }

    /**
     * @param maxEncryptedLength longest formatted value, in characters, that format will produce or
     *                           parse will accept
     * @throws IllegalArgumentException maxEncryptedLength is not positive
     */
    public DefaultFormatProviderImpl(int maxEncryptedLength) {
        if (maxEncryptedLength <= 0)
            throw new IllegalArgumentException("maxEncryptedLength must be positive; it is " + maxEncryptedLength + ".");
        this.maxEncryptedLength = maxEncryptedLength;
    }

    /** Longest formatted value, in characters, that format will produce or parse will accept. */
    public int getMaxEncryptedLength() {
        return maxEncryptedLength;
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalArgumentException the formatted value would exceed the limit
     */
    @Override
    public String format(KeyTrackingValue value) {
        var telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        try (var op = telemetry.startSpan(SpanNames.DataProtection.FORMAT_PROVIDER_FORMAT)) {
            try {
                Objects.requireNonNull(value, "value");
                if (telemetry.isSensitiveLoggingEnabled())
                    telemetry.logSensitiveOperation(op.span(), SpanNames.DataProtection.FORMAT_PROVIDER_FORMAT,
                            Attributes.of(KEY_VERSION, (long) value.keyVersion(), VALUE_LENGTH, (long) value.value().length));

                // Integer.toString is locale-independent: the version reads back identically anywhere.
                var version = Integer.toString(value.keyVersion());
                var length = ENC_PREFIX.length() + DELIMITER.length() * 2 + VERSION_PREFIX.length() + version.length()
                        + Base64ConversionUtility.getBase64Length(value.value());
                if (length > maxEncryptedLength)
                    throw new IllegalArgumentException("The formatted value would be " + length + " characters, over the " + maxEncryptedLength + "-character limit.");

                return ENC_PREFIX + DELIMITER + VERSION_PREFIX + version + DELIMITER + Base64ConversionUtility.toBase64String(value.value());
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    @Override
    public KeyTrackingValue parse(CharSequence encrypted) {
        var telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        try (var op = telemetry.startSpan(SpanNames.DataProtection.FORMAT_PROVIDER_PARSE)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.DataProtection.FORMAT_PROVIDER_PARSE,
                        Attributes.of(ENCRYPTED_LENGTH, (long) encrypted.length()));

            try {
                var segments = parseValid(encrypted);
                var value = new byte[Base64ConversionUtility.getBinaryLength(segments.base64())];
                Base64ConversionUtility.fromBase64(segments.base64(), value);
                return new KeyTrackingValue(segments.version(), value);
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    @Override
    public int getMaxDecryptedLength(CharSequence encrypted) {
        var telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        try (var op = telemetry.startSpan(SpanNames.DataProtection.FORMAT_PROVIDER_GET_MAX_DECRYPTED_LENGTH)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.DataProtection.FORMAT_PROVIDER_GET_MAX_DECRYPTED_LENGTH,
                        Attributes.of(ENCRYPTED_LENGTH, (long) encrypted.length()));

            try {
                var segments = parseValid(encrypted);
                return Base64ConversionUtility.getBinaryLength(segments.base64());
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    private record Segments(int version, CharSequence base64) {
    }

    // The segments of a well-formed encrypted value, whose payload is valid base64.
    private Segments parseValid(CharSequence encrypted) {
        var segments = parseSegments(encrypted);
        if (segments == null)
            throw new EncryptedFormatException(MALFORMED);

        if (!Base64ConversionUtility.isBase64(segments.base64()))
            throw new EncryptedFormatException("Encrypted value is not valid base64.");
        return segments;
    }

    // Shared by parse and getMaxDecryptedLength so both agree on exactly what counts as
    // well-formed - only getMaxDecryptedLength skips the actual base64 decode/allocation.
    private Segments parseSegments(CharSequence encrypted) {
        Objects.requireNonNull(encrypted, "encrypted");
        if (encrypted.length() > maxEncryptedLength)
            throw new EncryptedFormatException("Encrypted value is " + encrypted.length() + " characters, over the " + maxEncryptedLength + "-character limit.");

        var text = encrypted.toString();
        var firstDelimiter = text.indexOf(DELIMITER);
        if (firstDelimiter < 0)
            return null;

        var afterPrefix = firstDelimiter + DELIMITER.length();
        var secondDelimiter = text.indexOf(DELIMITER, afterPrefix);
        if (secondDelimiter < 0)
            return null;

        var prefix = text.substring(0, firstDelimiter);
        var versionSegment = text.substring(afterPrefix, secondDelimiter);
        var base64 = text.substring(secondDelimiter + DELIMITER.length());

        if (!prefix.equals(ENC_PREFIX) || !versionSegment.startsWith(VERSION_PREFIX))
            return null;

        // Only the canonical form format writes: ASCII digits with an optional leading '-' - no
        // whitespace, '+', or other scripts' digits.
        var digits = versionSegment.substring(VERSION_PREFIX.length());
        var start = digits.startsWith("-") ? 1 : 0;
        if (digits.length() == start)
            return null;
        for (var i = start; i < digits.length(); i++)
            if (digits.charAt(i) < '0' || digits.charAt(i) > '9')
                return null;

        int version;
        try {
            version = Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return null;
        }

        // Only the canonical form format writes: no whitespace.
        for (var i = 0; i < base64.length(); i++)
            if (Character.isWhitespace(base64.charAt(i)))
                return null;

        return new Segments(version, base64);
    }
}
