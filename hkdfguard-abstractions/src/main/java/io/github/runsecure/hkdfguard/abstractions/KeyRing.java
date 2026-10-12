package io.github.runsecure.hkdfguard.abstractions;

import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * A set of data encryption keys tracked by version, one of which is current. Anything that
 * encrypts asks for the current key on every operation, so it follows rotation automatically;
 * anything that decrypts asks for the exact version the value was encrypted under, so values
 * encrypted before a rotation still decrypt.
 */
public interface KeyRing {
    /**
     * The version new values are encrypted under - the highest one registered.
     *
     * @throws IllegalStateException no key has been registered yet
     */
    int getCurrentVersion();

    /**
     * The current version together with its key, read atomically.
     *
     * @throws IllegalStateException no key has been registered yet
     */
    VersionedKey getCurrent();

    /**
     * The key registered for {@code version}.
     *
     * @throws NoSuchElementException no key is registered for this version
     */
    DataEncryptionKey get(int version);

    /** The key registered for {@code version}, without throwing on a miss. */
    Optional<DataEncryptionKey> find(int version);
}
