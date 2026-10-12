package io.github.runsecure.hkdfguard.abstractions;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * A minimal KeyRing over fixed keys, for testing ProtectedCacheBase without the real key ring
 * (which lives in a module above Abstractions). The highest version added is current.
 */
final class FakeKeyRing implements KeyRing {
    private final Map<Integer, DataEncryptionKey> keys = new HashMap<>();
    private int currentVersion;

    FakeKeyRing(DataEncryptionKey key) {
        this(key, 1);
    }

    FakeKeyRing(DataEncryptionKey key, int version) {
        add(version, key);
    }

    void add(int version, DataEncryptionKey key) {
        if (keys.putIfAbsent(version, key) != null)
            throw new IllegalArgumentException("duplicate version " + version);
        currentVersion = Collections.max(keys.keySet());
    }

    void remove(int version) {
        keys.remove(version);
    }

    @Override
    public int getCurrentVersion() {
        return currentVersion;
    }

    @Override
    public VersionedKey getCurrent() {
        return new VersionedKey(currentVersion, keys.get(currentVersion));
    }

    @Override
    public DataEncryptionKey get(int version) {
        var key = keys.get(version);
        if (key == null)
            throw new NoSuchElementException("No key is registered for version " + version + ".");
        return key;
    }

    @Override
    public Optional<DataEncryptionKey> find(int version) {
        return Optional.ofNullable(keys.get(version));
    }
}
