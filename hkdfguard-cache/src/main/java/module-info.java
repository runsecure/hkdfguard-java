/**
 * Highly concurrent name-to-encrypted-value caches: {@link io.github.runsecure.hkdfguard.cache.ProtectedCacheImpl}
 * stores values encrypted under a key ring's current key,
 * {@link io.github.runsecure.hkdfguard.cache.ProtectedCacheCollectionImpl} reads through several sources in order,
 * and {@link io.github.runsecure.hkdfguard.cache.RemoteSecretCache} is the base of the caches over a remote
 * secret store, with {@link io.github.runsecure.hkdfguard.cache.SecretJsonBody} to take a secret out of a JSON
 * response body before an SDK can turn it into a String.
 */
module io.github.runsecure.hkdfguard.cache {
    requires transitive io.github.runsecure.hkdfguard.abstractions;
    requires io.github.runsecure.hkdfguard.remote;

    exports io.github.runsecure.hkdfguard.cache;
}
