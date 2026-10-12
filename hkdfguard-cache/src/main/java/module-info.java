/**
 * Highly concurrent name-to-encrypted-value caches: {@link io.github.runsecure.hkdfguard.cache.ProtectedCacheImpl}
 * stores values encrypted under a key ring's current key, and
 * {@link io.github.runsecure.hkdfguard.cache.ProtectedCacheCollectionImpl} reads through several sources in order.
 */
module io.github.runsecure.hkdfguard.cache {
    requires transitive io.github.runsecure.hkdfguard.abstractions;

    exports io.github.runsecure.hkdfguard.cache;
}
