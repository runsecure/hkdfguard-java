/**
 * A protected read-only cache over one HashiCorp Vault KV secrets engine:
 * {@link io.github.runsecure.hkdfguard.cache.hashicorpvault.HashiCorpVaultSecretCacheImpl} reads each
 * secret on its first lookup over Vault's HTTP API, through the JDK's {@code java.net.http}, and caches
 * every key it holds encrypted under the key ring's current key. The token every read is made with
 * comes from a {@link io.github.runsecure.hkdfguard.cache.hashicorpvault.VaultTokenProvider}, protected
 * by a data protector on the same ring.
 */
module io.github.runsecure.hkdfguard.cache.hashicorpvault {
    requires transitive io.github.runsecure.hkdfguard.cache;
    requires io.github.runsecure.hkdfguard.remote;
    requires transitive java.net.http;

    exports io.github.runsecure.hkdfguard.cache.hashicorpvault;
}
