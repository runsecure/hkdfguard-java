/**
 * Internal to HkdfGuard: {@link io.github.runsecure.hkdfguard.remote.JsonReader}, which reads a
 * secret out of a JSON response body without making it a String, and
 * {@link io.github.runsecure.hkdfguard.remote.VaultHttp}, the address, path, token and retry rules
 * the HashiCorp Vault cache and key wrapper share. Exported only to the modules that use them.
 */
module io.github.runsecure.hkdfguard.remote {
    requires io.github.runsecure.hkdfguard.abstractions;

    exports io.github.runsecure.hkdfguard.remote to
            io.github.runsecure.hkdfguard.cache,
            io.github.runsecure.hkdfguard.cache.hashicorpvault,
            io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;
}
