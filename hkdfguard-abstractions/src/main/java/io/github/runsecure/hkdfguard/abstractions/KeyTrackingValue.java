package io.github.runsecure.hkdfguard.abstractions;

import java.util.Arrays;
import java.util.Objects;

/**
 * An encrypted value together with the key version it was encrypted under - what an
 * {@link EncryptedFormatProvider} formats into, and parses back out of, the stored string.
 * <p>
 * Two values are equal when they have the same key version and the same ciphertext bytes;
 * {@link #toString()} gives the ciphertext's length, not its bytes.
 *
 * @param keyVersion the key ring version whose key encrypted {@code value}
 * @param value      the ciphertext
 */
public record KeyTrackingValue(int keyVersion, byte[] value) {
    public KeyTrackingValue {
        Objects.requireNonNull(value, "value");
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof KeyTrackingValue that && keyVersion == that.keyVersion && Arrays.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return 31 * Integer.hashCode(keyVersion) + Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "KeyTrackingValue[keyVersion=" + keyVersion + ", value=" + value.length + " bytes]";
    }
}
