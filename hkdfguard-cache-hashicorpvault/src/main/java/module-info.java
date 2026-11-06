/**
 * A protected read-only cache over one HashiCorp Vault KV secrets engine:
 * {@link io.github.runsecure.hkdfguard.cache.hashicorpvault.HashiCorpVaultSecretCacheImpl} reads each
 * secret on its first lookup over Vault's HTTP API, through the JDK's {@code java.net.http}, and caches
 * every key it holds encrypted under the key ring's current key. The token every read is made with
 * comes from a {@link io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultTokenProvider},
 * protected by a data protector on the same ring, and every request follows the rules every HkdfGuard
 * request to Vault does ({@link io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultHttp}).
 */
module io.github.runsecure.hkdfguard.cache.hashicorpvault {
    requires transitive io.github.runsecure.hkdfguard.cache;
    requires transitive io.github.runsecure.hkdfguard.integration.hashicorpvault;
    requires transitive java.net.http;

    exports io.github.runsecure.hkdfguard.cache.hashicorpvault;
}
