/**
 * Internal to HkdfGuard: {@link io.github.runsecure.hkdfguard.remote.JsonReader}, which reads a
 * secret out of a JSON response body without making it a String. Exported only to the modules that
 * use it. (The Vault rules it once held too are VaultHttp in hkdfguard-integration-hashicorpvault.)
 */
module io.github.runsecure.hkdfguard.remote {
    exports io.github.runsecure.hkdfguard.remote to
            io.github.runsecure.hkdfguard.cache,
            io.github.runsecure.hkdfguard.integration.hashicorpvault,
            io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;
}
