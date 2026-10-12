package io.github.runsecure.hkdfguard.abstractions;

import java.util.Objects;

/**
 * A key ring version together with its key - what {@link KeyRing#getCurrent()} returns.
 *
 * @param version the ring version
 * @param key     the key registered for it
 */
public record VersionedKey(int version, DataEncryptionKey key) {
    public VersionedKey {
        Objects.requireNonNull(key, "key");
    }
}
