package io.github.runsecure.hkdfguard.springboot;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.OptionalInt;
import org.springframework.core.env.PropertyResolver;

/**
 * Reveals Spring configuration values that hold protected secrets - the Spring counterpart of the
 * .NET {@code ProtectedConfigurationRoot}. Configuration itself only ever holds the formatted
 * ciphertext ({@code enc::v{version}::{base64}}); {@link #decrypt(String, char[])} reads it fresh
 * from the environment on every call and decrypts straight into the caller's buffer, which the
 * caller zeroes once done. Nothing is cached, so a refreshed property source takes effect
 * immediately, and no plaintext ever lands in an immutable {@code String}.
 *
 * <p>Each value is bound to the property name it is read by (see
 * {@link ProtectedConfigurationPurpose}): a value copied to a different property fails
 * authentication rather than being revealed. That name is used exactly as given, after the
 * purpose rule's ASCII upper-casing, so whoever encrypts a value - a pipeline, in any HkdfGuard
 * port - must use the same name the application reads it by. Use Spring's canonical form
 * ({@code my-service.api-key}): it is the form the {@code Environment} resolves, and it finds the
 * value whichever source supplies it, an environment variable ({@code MY_SERVICE_API_KEY})
 * included.
 *
 * <p>A protected value can live in any property source. Reading it through {@code @Value} or
 * {@code getProperty} yields the ciphertext, never the secret.
 */
public final class ProtectedEnvironment implements ProtectedReadOnlyCache {
    private static final AttributeKey<String> NAME = AttributeKey.stringKey(AttributeNames.NAME);

    private final PropertyResolver environment;
    private final KeyRingImpl keyRing;

    /**
     * @param environment the configuration to read protected values from, usually the
     *                    application's {@code Environment}
     * @param keyRing     the ring holding every key version the values were encrypted under
     */
    public ProtectedEnvironment(PropertyResolver environment, KeyRingImpl keyRing) {
        this.environment = Objects.requireNonNull(environment, "environment");
        this.keyRing = Objects.requireNonNull(keyRing, "keyRing");
    }

    /**
     * Decrypts the property's value into {@code result}.
     *
     * @return the chars written, or 0 if the property isn't set
     * @throws io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException the value isn't a
     *         protected value
     * @throws io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException the
     *         value was encrypted for a different property, or tampered with
     * @throws IllegalArgumentException {@code result} is too small, or {@code name} is empty or not
     *                                  valid UTF-16
     */
    @Override
    public int decrypt(String name, char[] result) {
        Objects.requireNonNull(result, "result");
        return traced(name, value -> protectorFor(name).decrypt(value, result));
    }

    /**
     * Decrypts the property's value into {@code result} as UTF-8 bytes. The decrypted chars pass
     * through a scratch buffer that is zeroed before this returns.
     *
     * @return the bytes written, or 0 if the property isn't set
     * @throws io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException the value isn't a
     *         protected value
     * @throws io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException the
     *         value was encrypted for a different property, or tampered with
     * @throws IllegalArgumentException {@code result} is too small for the value's UTF-8 bytes, or
     *                                  {@code name} is empty or not valid UTF-16
     */
    @Override
    public int decrypt(String name, byte[] result) {
        Objects.requireNonNull(result, "result");
        return traced(name, value -> {
            // The format's bound comes from the ciphertext's byte length, so it bounds the
            // plaintext's UTF-8 byte count as well as its char count.
            var protector = protectorFor(name);
            var chars = new char[protector.getMaxDecryptedLength(value)];
            try {
                var written = protector.decrypt(value, chars);
                return encodeUtf8(chars, written, result);
            } finally {
                ArrayUtility.zeroMemory(chars);
            }
        });
    }

    /**
     * @return a safe upper bound on the chars - and on the UTF-8 bytes - decrypting the property
     *         writes, or empty if the property isn't set
     * @throws io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException the value isn't a
     *         protected value
     */
    @Override
    public OptionalInt findMaxDecryptedLength(String name) {
        var value = environment.getProperty(name);
        return value == null ? OptionalInt.empty() : OptionalInt.of(protectorFor(name).getMaxDecryptedLength(value));
    }

    @FunctionalInterface
    private interface Reveal {
        int apply(String value);
    }

    private int traced(String name, Reveal reveal) {
        Objects.requireNonNull(name, "name");
        ComponentTelemetry telemetry = HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION;
        try (var op = telemetry.startSpan(SpanNames.EncryptedConfiguration.DECRYPT)) {
            if (telemetry.isSensitiveLoggingEnabled())
                telemetry.logSensitiveOperation(op.span(), SpanNames.EncryptedConfiguration.DECRYPT, Attributes.of(NAME, name));

            try {
                var value = environment.getProperty(name);
                return value == null ? 0 : reveal.apply(value);
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    // Bound to this one property, so a value copied in from another fails its tag check.
    private DataProtector protectorFor(String name) {
        return keyRing.createProtector(ProtectedConfigurationPurpose.forKey(name));
    }

    // Encodes straight into the caller's buffer: no intermediate byte[] that would need zeroing.
    private static int encodeUtf8(char[] chars, int length, byte[] result) {
        var output = ByteBuffer.wrap(result);
        var encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            var status = encoder.encode(CharBuffer.wrap(chars, 0, length), output, true);
            if (status.isError())
                status.throwException();
            if (status.isOverflow() || encoder.flush(output).isOverflow()) {
                // The part that fit is plaintext the caller won't be told about: erase it.
                ArrayUtility.zeroMemory(result, 0, output.position());
                throw new IllegalArgumentException("result is too small for the decrypted value's UTF-8 bytes; size it with findMaxDecryptedLength.");
            }
            return output.position();
        } catch (CharacterCodingException e) {
            // Unreachable for a value that decrypted: protectors only produce well-formed text.
            throw new IllegalStateException("The decrypted value is not well-formed UTF-16.", e);
        }
    }
}
