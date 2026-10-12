package io.github.runsecure.hkdfguard.abstractions;

import java.util.Objects;

/**
 * An encrypted value together with the key version it was encrypted under - what an
 * {@link EncryptedFormatProvider} formats into, and parses back out of, the stored string.
 *
 * @param keyVersion the key ring version whose key encrypted {@code value}
 * @param value      the ciphertext
 */
public record KeyTrackingValue(int keyVersion, byte[] value) {
    public KeyTrackingValue {
        Objects.requireNonNull(value, "value");
    }
}
